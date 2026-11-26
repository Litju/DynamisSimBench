#!/usr/bin/env bash
# Move one test command into the supervisor child of a delegated cgroup v2 root.
#
# This is test-host provisioning, not the worker mechanism. A production supervisor is
# placed in that child by its service manager (`Delegate=yes`); a CI runner has no such
# service, so the calling shell is moved once with the runner's passwordless sudo. The
# privilege is used only for the one `cgroup.procs` write; the command itself keeps the
# original user, environment and PATH. Every process it starts inherits the supervisor
# cgroup; the probe creates per-attempt siblings and kills those, never the supervisor.
set -euo pipefail

root="${DYNAMISBENCH_CGROUP_ROOT:-}"
if [ -z "$root" ]; then
    echo "DYNAMISBENCH_CGROUP_ROOT is not set" >&2
    exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
    echo "run this wrapper as the unprivileged supervisor user, not as root" >&2
    exit 2
fi
supervisor="$root/supervisor"
if [ ! -d "$supervisor" ]; then
    echo "the delegated supervisor cgroup $supervisor is absent" >&2
    exit 2
fi
if [ "$#" -eq 0 ]; then
    echo "usage: $0 <command> [arguments...]" >&2
    exit 2
fi

pid="$$"
if ! sudo bash -c 'printf "%s\n" "$1" > "$2/cgroup.procs"' _ "$pid" "$supervisor"; then
    echo "the supervisor cgroup did not accept this shell" >&2
    exit 2
fi
if ! grep -q "/$(basename "$supervisor")" /proc/self/cgroup; then
    echo "this shell is not in the delegated supervisor cgroup" >&2
    cat /proc/self/cgroup >&2
    exit 2
fi
exec "$@"
