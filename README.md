# Reverse Proxy Over SSH With ATProto

https://fedproxy.com

<img width="1490" height="2284" alt="Screenshot From 2026-05-03 18-39-52" src="https://github.com/user-attachments/assets/a9883a6f-eb0a-494f-8560-e05d1851f941" />

## Deployment

- https://github.com/openpubkey/opkssh/blob/main/docs/github-actions.md

```bash
wget -qO- "https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh" | sudo bash
echo "https://token.actions.githubusercontent.com github oidc" >> /etc/opk/providers
opkssh add deploy "repo:publicdomainrelay/atproto-reverse-proxy:ref:refs/heads/main" "https://token.actions.githubusercontent.com"
```
