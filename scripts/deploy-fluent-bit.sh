#!/usr/bin/env bash
# Install Fluent Bit as a systemd service on each named Droplet and ship its
# journald + app logs to a DigitalOcean Managed OpenSearch cluster over TLS.
#
# All OpenSearch config (host, port, user, password, CA cert) and each Droplet's
# Trusted Source firewall entry are derived automatically via doctl. The operator
# supplies only the cluster name/ID and a list of Droplet hostnames.
#
#   usage: DB_CLUSTER=<opensearch-cluster-name-or-id> \
#          ./deploy-fluent-bit.sh host1 [host2 ...]
#
# Optional env:
#   OPENSEARCH_INDEX  Logstash index prefix in OpenSearch        (default droplet-logs)
#   USE_PRIVATE       Use the cluster's VPC (private) host         (default off; set non-empty to enable)
#   SSH_USER          SSH login user on the Droplets               (default root)
#   SSH_HOST          Override SSH host (e.g. a resolvable FQDN)    (default Droplet public IP)
#
# Trusted Sources are NOT managed here: leave the cluster firewall empty (open) or
# pre-authorize the Droplets out of band.
set -xeuo pipefail

# ---- args / required env ----------------------------------------------------
if [ "$#" -eq 0 ]; then
  echo "usage: DB_CLUSTER=<name|id> $0 host1 [host2 ...]" >&2
  exit 1
fi
: "${DB_CLUSTER:?set DB_CLUSTER to the OpenSearch cluster name or ID}"

OPENSEARCH_INDEX="${OPENSEARCH_INDEX:-droplet-logs}"
# Note: no-colon default so an explicit USE_PRIVATE= (empty) stays empty/off. Only
# works if the cluster and the Droplets share a VPC; off by default.
USE_PRIVATE="${USE_PRIVATE-}"
SSH_USER="${SSH_USER:-root}"

command -v doctl >/dev/null 2>&1 || { echo "doctl not found on PATH" >&2; exit 1; }
command -v jq    >/dev/null 2>&1 || { echo "jq not found on PATH" >&2; exit 1; }

# ---- Phase 0: control machine, derive everything via doctl ------------------
rm -rf /tmp/fluent-bit-stage
mkdir -p /tmp/fluent-bit-stage

# Resolve cluster name -> ID (accept an ID being passed directly).
DB_ID="$(doctl databases list --format Name,ID --no-header \
  | awk -v n="$DB_CLUSTER" '$1==n || $2==n {print $2; exit}')"
: "${DB_ID:?could not resolve DB_CLUSTER '$DB_CLUSTER' to a cluster ID}"

# Connection details (Host Port User Password). --private keeps traffic on the VPC.
read -r OS_HOST OS_PORT OS_USER OS_PASS < <(
  doctl databases connection "$DB_ID" ${USE_PRIVATE:+--private} \
    --format Host,Port,User,Password --no-header
)
: "${OS_HOST:?empty host from doctl databases connection}"

# TLS trust differs by endpoint:
#  - PUBLIC host presents a Let's Encrypt cert -> verify with the Droplet's system
#    CA bundle (no custom CA needed).
#  - PRIVATE/VPC host presents DO's self-signed CA from `get-ca` -> push + use it.
if [ -n "$USE_PRIVATE" ]; then
  doctl databases get-ca "$DB_ID" -o json | jq -r .certificate | base64 --decode \
    > /tmp/fluent-bit-stage/os-ca.crt
  TLS_CA_FILE="/etc/fluent-bit/os-ca.crt"
else
  TLS_CA_FILE="/etc/ssl/certs/ca-certificates.crt"
fi

# hostname -> public IP map (Droplet names are not DNS-resolvable; SSH to the IP).
# Override SSH host per run with SSH_HOST.
DROPLET_MAP="$(doctl compute droplet list --format Name,PublicIPv4 --no-header)"

# ---- per-host loop ----------------------------------------------------------
cat <<'EOF' > /tmp/fluent-bit-stage/run-via-ssh.sh
set -xeuo pipefail
ssh -o StrictHostKeyChecking=accept-new "${SSH_TARGET}" bash -xe
EOF

for HOST in "$@"; do
  # Resolve public IP from the name (Trusted Sources are NOT managed by this script;
  # the cluster firewall must already permit these Droplets, or be left empty/open).
  DROPLET_IP="$(echo "$DROPLET_MAP" | awk -v n="$HOST" '$1==n {print $2; exit}')"
  # SSH to the IP (Droplet names are not resolvable); allow SSH_HOST override.
  export SSH_TARGET="${SSH_USER}@${SSH_HOST:-${DROPLET_IP:-$HOST}}"

  # Stage dir on the Droplet; push DO CA cert only when using the private endpoint.
  bash -xe /tmp/fluent-bit-stage/run-via-ssh.sh <<'REMOTE_EOF'
rm -rf /tmp/fb-stage
mkdir -p /tmp/fb-stage
REMOTE_EOF
  if [ -n "$USE_PRIVATE" ]; then
    scp -o StrictHostKeyChecking=accept-new \
      /tmp/fluent-bit-stage/os-ca.crt "${SSH_TARGET}":/tmp/fb-stage/os-ca.crt
  fi

  # Remote install + configure. Unquoted heredoc: OS_* / HOST expand locally so the
  # doctl-derived values land in the config. Single-quoted inner tee heredoc keeps
  # the Fluent Bit config literal (no remote shell expansion of its contents).
  bash -xe /tmp/fluent-bit-stage/run-via-ssh.sh <<REMOTE_EOF
set -xeuo pipefail

# 1. Install Fluent Bit if absent (brings its own fluent-bit.service unit).
if ! command -v fluent-bit >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
fi

# 2. Place DO CA cert (private endpoint only; public uses the system bundle).
sudo mkdir -p /etc/fluent-bit
if [ -f /tmp/fb-stage/os-ca.crt ]; then
  sudo mv /tmp/fb-stage/os-ca.crt /etc/fluent-bit/os-ca.crt
  sudo chmod 0644 /etc/fluent-bit/os-ca.crt
fi

# 3. Write config. Values below are expanded on the CONTROL machine.
sudo tee /etc/fluent-bit/fluent-bit.conf >/dev/null <<'FBCONF'
[SERVICE]
    Flush         5
    Daemon        Off
    Log_Level     info
    Parsers_File  parsers.conf

[INPUT]
    Name          systemd
    Tag           host.*
    Read_From_Tail On

[FILTER]
    Name          record_modifier
    Match         *
    Record        hostname ${HOST}

[OUTPUT]
    Name          opensearch
    Match         *
    Host          ${OS_HOST}
    Port          ${OS_PORT}
    HTTP_User     ${OS_USER}
    HTTP_Passwd   ${OS_PASS}
    tls           On
    tls.ca_file   ${TLS_CA_FILE}
    Suppress_Type_Name On
    Logstash_Format On
    Logstash_Prefix ${OPENSEARCH_INDEX}
FBCONF

# 4. Enable + (re)start the service.
sudo systemctl daemon-reload
sudo systemctl enable --now fluent-bit
sudo systemctl restart fluent-bit
sudo systemctl status --no-pager fluent-bit
REMOTE_EOF

  echo "==> ${HOST}: Fluent Bit shipping to ${OS_HOST}:${OS_PORT} index ${OPENSEARCH_INDEX}-*"
done

echo "Done. Verify: ssh ${SSH_USER}@<host> journalctl -u fluent-bit -f"
