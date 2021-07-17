#!/bin/bash

# we want exit immediately if any command fails and we want error in piped commands to be preserved
set -eo pipefail

# are we running from terminal?
is_term="test -t 1"

pkg_name="github-act-runner"
runner_bin=/usr/bin/${pkg_name}/runner
runners_dir=~/.config/${pkg_name}/runners

systemctl_user_opt=
if [ "$(id --user)" -eq 0 ]; then
    echo "running as root"
    systemctl_cmd=systemctl
else
    echo "running as user '$(id --user --name)'"
    systemctl_user_opt=--user
    systemctl_cmd="systemctl ${systemctl_user_opt}"
fi

function error {
    local message=$1
    local exit_code=$2

    if [ -z "$exit_code" ]; then
        exit_code=1
    fi

    $is_term && printf "\t\e[1;31mERROR\e[0m: $message\n" || printf "\tERROR: $message\n"
    exit $exit_code
}

cur_err_trap=
function add_to_err_trap {
    local cmd="$1;"

    cur_err_trap="${cur_err_trap} $cmd"
    trap "${cur_err_trap}" ERR
}

declare -A commands=( \
        [ls]="list registered runners" \
        [new]="register new runner" \
        [rm]="remove registered runner" \
        [stop]="stop runner service" \
        [start]="start runner service" \
    )

while [[ $# > 0 ]] ; do
	case $1 in
		--help)
			echo "usage:"
			echo "  $(basename $0) [<options>] <command> [--help] [<command-options>] [...]"
			echo ""
			echo "options:"
            echo "  --help  show this help text and do nothing."
            echo ""
            echo "commands:"
            for i in "${!commands[@]}"; do {
                echo "  $i        ${commands[$i]}"
            } done
			exit 0
			;;
		*)
            command=$1
            [ ! -z "${commands[$command]}" ] || error "unknown command: $command"
			;;
	esac
	[[ $# > 0 ]] && shift;

    if [ ! -z "$command" ]; then break; fi
done

[ ! -z "$command" ] || error "command is not given"

function handle_new_command {
    # define required options to empty values
    declare -A local opts=( \
        [owner]= \
        [name]= \
        [token]= \
    )

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
			    echo "	$(basename $0) <...> add <options>"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                echo "  --owner   github repo (e.g. 'my_user/my_repo') or organization (e.g. 'my_org')."
                echo "  --name    new runner name."
                echo "  --labels  comma separated list of runner labels, e.g. 'label1,label1,label3'."
                echo "  --token   github runner registration token."
                exit 0
                ;;
            --owner)
                shift
                opts[owner]=$1
                ;;
            --name)
                shift
                opts[name]=$1
                ;;
            --token)
                shift
                opts[token]=$1
                ;;
            --labels)
                shift
                opts[labels]=$1
                ;;
            *)
                error "unknown option: $1"
                ;;
        esac
        [[ $# > 0 ]] && shift;
    done

    for opt in ${!opts[@]}; do
        [ ! -z "${opts[$opt]}" ] || error "missing option: --$opt"
    done

    if [ ! -z "$systemctl_user_opt" ]; then
        # running as non-root user
        # check that the user is in 'docker' group"
        if [ -z "$(groups | grep docker)" ]; then
            error "user '$(id --user --name)' is not in 'docker' group, install docker and add the user to the group"
        fi
    fi

    mkdir --parents $runners_dir

    local owner_dot=(${opts[owner]//\//.})

    local runner_id=${opts[name]}.${owner_dot}

    local runner_dir="${runners_dir}/${runner_id}"
    if [ -d "$runner_dir" ]; then
        error "unable to add runner 'id = ${runner_id}', runner already exists"
    fi

    echo "new runner config will be placed to $runner_dir"

    local labels=
    if [ ! -z "${opts[labels]}" ]; then
        # NOTE: that runner_bin has '--label' key, not '--labels', TODO: fix that in runner_bin?
        labels="--label ${opts[labels]}"
    fi

    mkdir --parents $runner_dir

    # remove the new runner dir in case of ERROR
    add_to_err_trap "rm --recursive --force $runner_dir"

    local url=https://github.com/${opts[owner]}

    (
        cd $runner_dir &&
        $runner_bin configure --url $url --name ${opts[name]} --token ${opts[token]} $labels
        echo "\$? = $?"
    )

    if [ -z "$systemctl_user_opt" ]; then
        # root
        local systemd_units_dir=/etc/systemd/system/
    else
        # user
        local systemd_units_dir=~/.config/systemd/user/
        mkdir --parents $systemd_units_dir
    fi

    local runner_service_name=${pkg_name}.${runner_id}
    local runner_service_file=${runner_service_name}.service
    local restarter_service_file=${runner_service_name}.restarter.service
    local restarter_path_file=${runner_service_name}.path

    [ ! -f "${systemd_units_dir}${runner_service_file}" ] || error "ASSERT(! -f ${systemd_units_dir}${runner_service_file}) failed"

    echo "\
[Unit]
Description=${pkg_name} '${opts[owner]}/${opts[name]}'
After=network.target

[Service]
ExecStart=/usr/bin/${pkg_name}/runner run
WorkingDirectory=$runner_dir
KillMode=process
KillSignal=SIGINT
TimeoutStopSec=60min

[Install]
WantedBy=multi-user.target
" > ${systemd_units_dir}${runner_service_file}

    add_to_err_trap "rm ${systemd_units_dir}${runner_service_file}"

    [ ! -f "${systemd_units_dir}${restarter_service_file}" ] || error "ASSERT(! -f ${systemd_units_dir}${restarter_service_file}) failed"

    echo "\
[Unit]
Description=${pkg_name} '${opts[owner]}/${opts[name]}' restarter
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart ${runner_service_file}

[Install]
WantedBy=multi-user.target
" > ${systemd_units_dir}${restarter_service_file}

    add_to_err_trap "rm ${systemd_units_dir}${restarter_service_file}"

    [ ! -f "${systemd_units_dir}${restarter_path_file}" ] || error "ASSERT(! -f ${systemd_units_dir}${restarter_path_file}) failed"

    echo "\
[Path]
PathModified=/usr/bin/${pkg_name}/runner

[Install]
WantedBy=multi-user.target
" > ${systemd_units_dir}${restarter_path_file}

    add_to_err_trap "rm ${systemd_units_dir}${restarter_path_file}"

    $systemctl_cmd daemon-reload 

    echo "service status ="
    $systemctl_cmd status ${runner_service_file} || echo "\$? = $?"
    echo "restarter status ="
    $systemctl_cmd status ${restarter_service_file} || echo "\$? = $?"
    echo "path status ="
    $systemctl_cmd status ${restarter_path_file} || echo "\$? = $?"

    echo "service start ="
    $systemctl_cmd status ${runner_service_file} || echo "\$? = $?"
    echo "restarter start ="
    $systemctl_cmd status ${restarter_service_file} || echo "\$? = $?"
    echo "path start ="
    $systemctl_cmd status ${restarter_path_file} || echo "\$? = $?"

    # $systemctl_cmd enable 

    # TODO: remove
    # [ -z "ewf" ]
}

function handle_ls_command {
    if [ ! -d "$runners_dir" ]; then
        return
    fi

    # echo "runners_dir = $runners_dir"
    local runners=$(ls --almost-all $runners_dir)
    # echo "runners = $runners"

    for id in $runners; do
        local service_name="${pkg_name}.${id}.service"
        # echo "service_name = $service_name"
        local is_enabled=$($systemctl_cmd is-enabled ${service_name} || true)
        local is_active=$($systemctl_cmd is-active ${service_name} || true)
        # local is_failed=$($systemctl_cmd is-failed ${service_name} || echo "$?")

        if $is_term; then
            if [ "$is_enabled" == "enabled" ]; then
                is_enabled="\e[1;32m$is_enabled\e[0m"
            else
                is_enabled="\e[1;90m$is_enabled\e[0m"
            fi

            if [ "$is_active" == "active" ]; then
                is_active="\e[1;32m$is_active\e[0m"
            elif [ "$is_active" == "failed" ]; then
                is_active="\e[1;31m$is_active\e[0m"
            else
                is_active="\e[1;90m$is_active\e[0m"
            fi
        fi

        printf "$id $is_enabled $is_active\n"
    done
}

handle_${command}_command $@
