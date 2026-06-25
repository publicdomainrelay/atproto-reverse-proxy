set -xeuo pipefail
ssh -o StrictHostKeyChecking=accept-new "${SSH_TARGET}" bash -xe
