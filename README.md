# Reverse Proxy Over SSH With ATProto

https://fedproxy.com

## Auto Domain on Boot

Could be combined with https://github.com/digitalocean-labs/droplet-oidc-poc/tree/main#atproto-login-and-rbac-configuration to automate getting a Droplet a resolvable domain after boot and doing service discovery via ATProto, or etc by:

- Configure RBAC policies for Droplet workload identity reverse proxy to allow [Droplet to allow calling `com.atproto.repo.createRecord` with `service: my-cool-service`](https://github.com/digitalocean-labs/droplet-oidc-poc/blob/ea8be96b16f309ad240cdbfe59a0c91d0807f426/scripts/setup.sh#L34-L41)

- Spin Droplet using workload identity reverse proxy

- Via Droplet `user_data` create ssh key pair and run example for `/xrpc/com.atproto.repo.createRecord` using [`com.fedproxy.sshPublicKey`](https://github.com/publicdomainrelay/atproto-reverse-proxy/blob/c9f49516611879aaf62ce1806f8e6cdf721b2c12/src/javascript/fedproxy-ssh-public-keys/main.js#L237-L247)

- `curl` down the systemd service file (**TODO**)

- Have the Droplet `systemctl enable --now my-cool-sevice.handle.example.com@fedproxy.service`

<img width="1490" height="2284" alt="Screenshot From 2026-05-03 18-39-52" src="https://github.com/user-attachments/assets/a9883a6f-eb0a-494f-8560-e05d1851f941" />

## Deployment

- https://github.com/openpubkey/opkssh/blob/main/docs/github-actions.md

> **TODO** `doctl compute droplet create --user-data $THIS_FILE ...`

```bash
ssh root@fedproxy.com bash -xe <<'EOF'
wget -qO- "https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh" | sudo bash
echo "https://token.actions.githubusercontent.com github oidc" >> /etc/opk/providers
opkssh add deploy "repo:publicdomainrelay/atproto-reverse-proxy:ref:refs/heads/main" "https://token.actions.githubusercontent.com"
useradd -s $(which bash) -m deploy
usermod -G sudo deploy
echo "deploy   ALL=(ALL:ALL) NOPASSWD:ALL" | tee -a /etc/sudoers
EOF
```

## 

## Notes

- https://openid.net/specs/openid-federation-1_0.html

  - ^ long term

  - short term experiment with oidc workload identity tokens

  - Could use -L (removed from agi.sock but could add back) to workload identity reverse proxy. Since the workload id oauth token is replaced by the atp reocrd pki with public key links, also this ensures that only the single open connection has access, token can't be stolen, since connection has to be live and only via ssh -L.

  - Minimally, provide example OIDC server that can issue tokens locally on connect up client and offer an endpoint at .well-known/openid-configureation (potentially need proxy config with multiple -R)

    - This would enable a client-server to easily issue workload ID Tokens for other things on it so it doesn't need secrets provisioned (or they unlock via secondary mechs like openbao)

- atrprp.chadig.com

  - service.handle.com.atrprp.chadig.com

- sh.tagled.publicKey

- emit firehose event if we need a reconnect (example: scalling to more nodes)

- ssh -R or -L (which one is it again?)

- if web of trust via vouches says you're good then enable for user

- https://github.com/publicdomainrelay/sshai/blob/b309c3d64498985b132f61543dde1929cbcdb687/src/sshd/agi_sshd.go#L81

  - ssh reverse proxy

- could support only certain software via attestations or workload id and trust rings

- User adds record for service

  - User (or service via workload id) adds ssh key

  - backlinks ssh keys to service

- proxy gets request over ssh

  - splits service.handle.com

  - resolves service records

  - checks ssh keys valid using backlinks to keys

  - ensures caddy reverse proxies to unix socket (maybe future support for round robin if multiple active connections)

- User goes to atprp.chadig.com

  - adds service name and ssh keys for backend(s)

  - PoC round 1 use https://pdsls.dev to create records

    - https://pdsls.dev/at://did:plc:5svqtrhheairglgiiyvutzik/sh.tangled.publicKey/3mgwzjaw6vu22

    - https://constellation.microcosm.blue/xrpc/blue.microcosm.links.getBacklinks?subject=at%3A%2F%2Fdid%3Aplc%3Aa4pqq234yw7fqbddawjo7y35%2Fapp.bsky.feed.post%2F3m237ilwc372e&source=app.bsky.feed.like%3Asubject.uri&limit=16

- on system we want to reverse proxy to

  - uv run or curl to bash for install

  - `UserKnownHostsFile` download public key over HTTPS

  - install systemd unit files to restart ssh proxy to local port on restart

    - https://github.com/johnandersen777/dotfiles/blob/8726281467c5ababe53fc1e2d869a8e897c89cf8/forge-install.sh#L59-L74
