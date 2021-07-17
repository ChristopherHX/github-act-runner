#!/bin/bash

# this script is to be invoked by restarter systemd service to restart a runner due
# to the runner executable file change, perhaps due to update

script_dir="$(dirname $0)/"

# are we root?
is_root="[ $(id --user) -eq 0 ]"

if $is_root; then
    systemctl_cmd="systemctl"
else
    systemctl_cmd="systemctl --user"
fi

service_name=$1

[ -z "$service_name" ] && echo "service name argument is not given" && exit 1 || true

if [ -f "${script_dir}runner" ]; then
    # just in case user has manually stopped the runner via 'github-act-runner.sh stop ...'
    # check that the service is enabled and restart the service only if it is enabled
    is_enabled=$($systemctl_cmd is-enabled ${service_name} || true)
    if [ "$is_enabled" == "enabled" ]; then
        $systemctl_cmd restart $service_name
    fi
else
    # file has been deleted, perhaps the github-act-runner package was uninstalled,
    # no need to restart the service in this case, stop the service.
    $systemctl_cmd stop $service_name
fi
