#!/bin/bash

script_dir="$(dirname $0)/"

# are we root?
is_root="[ $(id --user) -eq 0 ]"

if $is_root; then
    systemctl_cmd="systemctl"
else
    systemctl_cmd="${systemctl_cmd} --user"
fi

service_name=$1

[ ! -z "$service_name" ] || echo "service name argument is not given" && exit 1

if [ -f "${script_dir}runner" ]; then
    $systemctl_cmd try-restart $service_name
else
    # file has been deleted
    $systemctl_cmd stop $service_name
fi
