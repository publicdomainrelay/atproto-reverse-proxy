#!/usr/bin/env bash
set -xeuo pipefail

export SSH_TARGET="${SSH_TARGET:-root@fedproxy.com}"

echo "${CF_API_TOKEN}"

cd src/golang
rm -rf target/
mkdir -p target/
go build -o target ./cmd/...
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
sudo rm -rf /var/www/html
sudo mkdir -pv /var/www/
sudo mkdir -pv /opt/caddy
sudo chown -R caddy:caddy /opt/caddy

sudo mv /tmp/fedproxy-ssh-public-keys /var/www/html
sudo mv /tmp/stage/Caddyfile /etc/caddy/Caddyfile
sudo mv /tmp/stage/atprp-ssh-relay /usr/bin/atprp-ssh-relay
sudo mv /tmp/stage/caddy-check-dns-from-config /usr/bin/caddy-check-dns-from-config
sudo mv /tmp/stage/oauth-client-webapp /usr/bin/oauth-client-webapp

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
WorkingDirectory=/var/run
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo wget "https://github.com/caddyserver/xcaddy/releases/download/v0.4.5/xcaddy_0.4.5_linux_amd64.deb"
echo sudo dpkg -i xcaddy_0.4.5_linux_amd64.deb
echo apt-get install -y golang
echo xcaddy build --with github.com/caddy-dns/cloudflare
echo mv caddy /usr/bin/caddy

sudo systemctl daemon-reload

sudo systemctl enable --now atprp-ssh-relay.service
sudo systemctl restart atprp-ssh-relay
sudo systemctl status --no-pager atprp-ssh-relay.service

sudo systemctl enable --now caddy-check-dns-from-config.service
sudo systemctl restart caddy-check-dns-from-config
sudo systemctl status --no-pager caddy-check-dns-from-config.service

sudo systemctl enable --now oauth-client-webapp.service
sudo systemctl restart oauth-client-webapp
sudo systemctl status --no-pager oauth-client-webapp.service


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
sudo systemctl enable --now caddy
sudo systemctl restart caddy
sudo systemctl status --no-pager caddy.service
REMOTE_EOF
