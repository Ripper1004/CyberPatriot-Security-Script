#!/usr/bin/env bash
# Test harden.sh in throwaway Docker containers.
#
#   bash tests/linux/run-tests.sh                 # Debian 12, Ubuntu 22.04 and 24.04, Mint 21.3
#   bash tests/linux/run-tests.sh debian:12       # just one image
#
# If you are behind an HTTPS proxy with its own certificate, set
#   TEST_CA=/path/to/ca.crt  and  https_proxy=http://host:port
#
# Containers don't run systemd, so starting/stopping services, the firewall and
# live kernel settings are reported as FAILED there - that is expected.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
IMAGES=("$@")
[ ${#IMAGES[@]} -eq 0 ] && IMAGES=(debian:12 ubuntu:22.04 ubuntu:24.04 linuxmintd/mint21.3-amd64)

extra=()
if [ -n "${TEST_CA:-}" ]; then
  extra+=(--network host -v "$TEST_CA:/ca.crt:ro" -e "https_proxy=${https_proxy:-}")
fi

status=0
for img in "${IMAGES[@]}"; do
  echo "################ $img ################"
  if docker run --rm "${extra[@]}" -v "$REPO:/repo:ro" "$img" bash /repo/tests/linux/in-container.sh; then
    echo "################ $img: ALL PASSED"
  else
    echo "################ $img: FAILURES"; status=1
  fi
done
exit $status
