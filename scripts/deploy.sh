#!/usr/bin/env bash
set -xeuo pipefail

export SSH_TARGET="${SSH_TARGET:-root@fedproxy.com}"

echo "${CF_API_TOKEN}"

cd src/golang
rm -rf target/
mkdir -p target/
GOOS=linux GOARCH=amd64 go build -o target ./cmd/...
cd ../..

cat <<'EOF' > run-via-ssh.sh
set -xeuo pipefail
ssh -o StrictHostKeyChecking=accept-new "${SSH_TARGET}" bash -xe
EOF

bash -xe run-via-ssh.sh <<'EOF'
echo sudo apt-get update
echo sudo apt-get install -y caddy
rm -rf /tmp/stage
rm -rf /tmp/fedproxy-ssh-public-keys
mkdir -p /tmp/stage
EOF

scp -r -o StrictHostKeyChecking=accept-new src/javascript/fedproxy-ssh-public-keys "${SSH_TARGET}":/tmp/
scp -o StrictHostKeyChecking=accept-new src/golang/Caddyfile "${SSH_TARGET}":/tmp/stage/Caddyfile
scp -o StrictHostKeyChecking=accept-new src/golang/target/atprp-ssh-relay "${SSH_TARGET}":/tmp/stage/atprp-ssh-relay
scp -o StrictHostKeyChecking=accept-new src/golang/target/caddy-check-dns-from-config "${SSH_TARGET}":/tmp/stage/caddy-check-dns-from-config
scp -o StrictHostKeyChecking=accept-new src/golang/target/oauth-client-webapp "${SSH_TARGET}":/tmp/stage/oauth-client-webapp


bash -xe run-via-ssh.sh <<REMOTE_EOF
# Create swapfile if absent — 4 GB droplet has no swap by default,
# which means OOM killer is the only escape valve when memory pressure hits.
if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "Created and enabled 2G swapfile"
else
  echo "Swapfile already exists, skipping"
fi

sudo rm -rf /var/www/html
sudo mkdir -pv /var/www/
sudo mkdir -pv /opt/caddy
sudo chown -R caddy:caddy /opt/caddy

sudo mv /tmp/fedproxy-ssh-public-keys /var/www/html
sudo mv /tmp/stage/Caddyfile /etc/caddy/Caddyfile
sudo mv /tmp/stage/atprp-ssh-relay /usr/bin/atprp-ssh-relay
sudo mv /tmp/stage/caddy-check-dns-from-config /usr/bin/caddy-check-dns-from-config
sudo mv /tmp/stage/oauth-client-webapp /usr/bin/oauth-client-webapp

# Install deno if absent (xrpc-relay-server runs from source via deno, no compile).
if ! command -v deno >/dev/null 2>&1; then
  command -v unzip >/dev/null 2>&1 || sudo apt-get install -y unzip
  curl -fsSL https://deno.land/install.sh | sudo DENO_INSTALL=/usr/local sh
fi

# Clone (or update) latest xrpc-relay source. Run server.ts directly with deno.
sudo rm -rf /opt/xrpc-relay
sudo git clone --depth 1 https://github.com/publicdomainrelay/compute-contract-reference-implementation-poc /opt/xrpc-relay

sudo tee /etc/systemd/system/caddy-check-dns-from-config.service <<'EOF'
[Unit]
Description=atprp-ssh-relay
After=network.target caddy.service
Wants=caddy.service
[Service]
Type=simple
ExecStart=/usr/bin/caddy-check-dns-from-config
Restart=on-failure
Environment=LISTEN_ADDR=127.0.0.1:5555
Environment=CADDY_SOCK=/opt/caddy/caddy-admin.sock
WorkingDirectory=/var/run
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/oauth-client-webapp.service <<'EOF'
[Unit]
Description=atprp-ssh-relay
After=network.target caddy.service
Wants=caddy.service
[Service]
Type=simple
ExecStart=/usr/bin/oauth-client-webapp
Restart=on-failure
Environment=THIS_ENDPOINT=https://rp.fedproxy.com
Environment=LISTEN_SOCKET=/opt/caddy/web-ui.sock
Environment=DATABASE_URI=sqlite:////opt/caddy/oauth-client-webapp.db
Environment=GOMEMLIMIT=512MiB
WorkingDirectory=/var/run
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/atprp-ssh-relay.service <<EOF
[Unit]
Description=atprp-ssh-relay
After=network.target caddy.service
Wants=caddy.service
[Service]
Type=simple
ExecStart=/usr/bin/atprp-ssh-relay
Restart=on-failure
Environment=CF_API_TOKEN="${CF_API_TOKEN}"
Environment=THIS_ENDPOINT=fedproxy.com
Environment=CADDY_SOCK=/opt/caddy/caddy-admin.sock
Environment=GOMEMLIMIT=3GiB
WorkingDirectory=/var/run
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/xrpc-relay-server.service <<EOF
[Unit]
Description=xrpc-relay-server
After=network.target caddy.service
Wants=caddy.service

[Service]
Type=simple
ExecStart=/usr/local/bin/deno run --allow-net --allow-env --allow-read --allow-write --allow-sys /opt/xrpc-relay/src/typescript/xrpc-relay/server.ts
Environment=UNIX_SOCKET=/opt/caddy/xrpc-relay-server.sock
Restart=on-failure
Environment=HOSTNAME=xrpc.fedproxy.com
WorkingDirectory=/opt/xrpc-relay/src/typescript/xrpc-relay
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Ensure Caddy is installed and carries the cloudflare DNS module. atprp-ssh-relay
# needs DNS-01 (cloudflare) to issue certs for multi-level subdomains like
# svc.handle.fedproxy.com; without the module Caddy rejects the automation policy
# the relay pushes and no cert is ever minted ("no certificate matching TLS ClientHello").
# Idempotent: only (re)build when the running binary lacks dns.providers.cloudflare.
if ! caddy list-modules 2>/dev/null | grep -q 'dns.providers.cloudflare'; then
  echo "cloudflare DNS module missing -- installing Caddy + building with xcaddy"

  sudo apt-get update

  # Base Caddy package supplies the caddy user/group and default dirs. Install
  # from the official Cloudsmith repo if no caddy binary exists yet.
  if ! command -v caddy >/dev/null 2>&1; then
    sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
    sudo apt-get update
    sudo apt-get install -y caddy
  fi

  # xcaddy needs Go.
  command -v go >/dev/null 2>&1 || sudo apt-get install -y golang-go

  # Install xcaddy if absent.
  if ! command -v xcaddy >/dev/null 2>&1; then
    wget -q "https://github.com/caddyserver/xcaddy/releases/download/v0.4.5/xcaddy_0.4.5_linux_amd64.deb" -O /tmp/xcaddy.deb
    sudo dpkg -i /tmp/xcaddy.deb
  fi

  # Build a Caddy with the cloudflare DNS provider and swap it in. Replacing the
  # binary in place is safe while caddy runs; the restart at the end of this
  # script execs the new binary.
  xcaddy build --with github.com/caddy-dns/cloudflare --output /tmp/caddy-cloudflare
  sudo mv /tmp/caddy-cloudflare /usr/bin/caddy
  sudo chmod 0755 /usr/bin/caddy

  # Fail loudly if the build did not actually include the module.
  caddy list-modules 2>/dev/null | grep -q 'dns.providers.cloudflare' || { echo "ERROR: cloudflare DNS module still missing after build"; exit 1; }
  echo "Caddy now has dns.providers.cloudflare"
else
  echo "Caddy already has dns.providers.cloudflare -- skipping build"
fi

# TODO This whole workflow is a bunch of hax
sudo tee /usr/lib/systemd/system/caddy.service <<'EOF'
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=root
Group=root
Environment=CF_API_TOKEN="${CF_API_TOKEN}"
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
# PrivateTmp=true
# ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

# ORDER MATTERS. Caddy must come up FIRST and be the stable target. The relay
# and the per-FQDN routes/DNS-01 policy it (and reconnecting clients) push live
# only in Caddy's runtime config. If Caddy is restarted AFTER the relay, that
# restart wipes every dynamic route + the on_demand TLS policy, and the relay's
# already-established SSH sessions never re-push them -> certs silently stop
# being issued ("no certificate available"). So: caddy -> gate -> relay -> oauth.
sudo systemctl enable --now caddy
sudo systemctl restart caddy
sudo systemctl status --no-pager caddy.service

# On-demand TLS ask gate. Reads Caddy's admin socket, so Caddy must be up first.
sudo systemctl enable --now caddy-check-dns-from-config.service
sudo systemctl restart caddy-check-dns-from-config
sudo systemctl status --no-pager caddy-check-dns-from-config.service

# Relay last among the Caddy-dependent services: at startup it installs the
# wildcard DNS-01 on_demand policy + catch-all onto the now-stable Caddy and
# keeps it (and every forward route) reconciled.
sudo systemctl enable --now atprp-ssh-relay.service
sudo systemctl restart atprp-ssh-relay
sudo systemctl status --no-pager atprp-ssh-relay.service

sudo systemctl enable --now xrpc-relay-server.service
sudo systemctl restart xrpc-relay-server
sudo systemctl status --no-pager xrpc-relay-server.service

sudo systemctl enable --now oauth-client-webapp.service
sudo systemctl restart oauth-client-webapp
sudo systemctl status --no-pager oauth-client-webapp.service
REMOTE_EOF
