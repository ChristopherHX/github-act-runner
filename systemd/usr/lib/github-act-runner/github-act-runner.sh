#!/bin/bash

# we want exit immediately if any command fails and we want error in piped commands to be preserved
set -eo pipefail

# are we running from terminal?
is_term="test -t 1"

# are we root?
is_root="[ $(id --user) -eq 0 ]"

pkg_name="github-act-runner"
runner_bin_dir=/usr/lib/${pkg_name}/
runner_bin=${runner_bin_dir}runner
runners_dir=~/.config/${pkg_name}/runners/

systemctl_cmd="systemctl"
if $is_root; then
    echo "running as root"
    systemd_units_dir=/etc/systemd/system/
else
    echo "running as user '$(id --user --name)'"
    systemctl_cmd="${systemctl_cmd} --user"
    systemd_units_dir=~/.config/systemd/user/
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

function start_runner_service {
    local id=$1

    local runner_service_name=${pkg_name}.${id}
    local runner_service_file=${runner_service_name}.service
    local restarter_service_file=${runner_service_name}.restarter.service
    local restarter_path_file=${runner_service_name}.path

    $systemctl_cmd --quiet enable $runner_service_file
    $systemctl_cmd --quiet start $runner_service_file

    $systemctl_cmd --quiet enable $restarter_service_file

    $systemctl_cmd --quiet enable $restarter_path_file
    $systemctl_cmd --quiet start $restarter_path_file
}

function stop_runner_service {
    local id=$1

    local runner_service_name=${pkg_name}.${id}
    local runner_service_file=${runner_service_name}.service
    local restarter_service_file=${runner_service_name}.restarter.service
    local restarter_path_file=${runner_service_name}.path

    $systemctl_cmd --quiet stop $restarter_path_file
    $systemctl_cmd --quiet disable $restarter_path_file

    $systemctl_cmd --quiet stop $restarter_service_file
    $systemctl_cmd --quiet disable $restarter_service_file

    $systemctl_cmd --quiet stop $runner_service_file
    $systemctl_cmd --quiet disable $runner_service_file
}

function assert_runner_exists {
    local id=$1

    local runner_dir=${runners_dir}${id}

    # check that runner exists
    [ -d "${runner_dir}" ] || error "runner 'id = ${id}' does not exist"
}

function handle_new_command {
    # define required options to empty values
    declare -A local opts=( \
        [owner]= \
        [name]= \
        [token]= \
        [domain]="https://github.com" \
    )

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> add <options>"
                echo ""
                echo "options:"
                echo "  --help          show this help text and do nothing."
                echo "  --domain        github domain (e.g. 'https://github.somedomain.org') default 'https://github.com'."
                echo "  --owner         github repo (e.g. 'my_user/my_repo') or organization (e.g. 'my_org')."
                echo "  --name          new runner name."
                echo "  --labels        comma separated list of runner labels, e.g. 'label1,label1,label3'."
                echo "  --token         github runner registration token."
                echo "  --runnergroup   runner group name."
                exit 0
                ;;
            --domain)
                shift
                opts[domain]=$1
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
            --runnergroup)
                shift
                opts[runnergroup]=$1
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

    if ! $is_root; then
        # running as non-root user
        # check that the user is in 'docker' group"
        if [ -z "$(groups | grep docker)" ]; then
            error "user '$(id --user --name)' is not in 'docker' group, install docker and add the user to the group"
        fi
    fi

    mkdir --parents $runners_dir

    local owner_dot=(${opts[owner]//\//.})

    local runner_id=${opts[name]}.${owner_dot}

    local runner_dir="${runners_dir}${runner_id}"
    if [ -d "$runner_dir" ]; then
        error "unable to create new runner: runner 'id = ${runner_id}' already exists"
    fi

    # echo "new runner config will be placed to $runner_dir"

    local labels=
    if [ ! -z "${opts[labels]}" ]; then
        labels="--labels ${opts[labels]}"
    fi

    local runnergroup=
    if [ ! -z "${opts[runnergroup]}" ]; then
        runnergroup="--runnergroup ${opts[runnergroup]}"
    fi

    mkdir --parents $runner_dir

    # remove the new runner dir in case of ERROR
    add_to_err_trap "rm --recursive --force $runner_dir"

    local url=${opts[domain]}/${opts[owner]}

    (
        cd $runner_dir &&
        if ! $runner_bin configure --unattended --url $url --name ${opts[name]} --token ${opts[token]} $labels $runnergroup; then
            error "failed creating runner on github"
        fi
        # echo "\$? = $?"
    )

    # We add 3 service files. The idea is that one service file will be running the runner service itself.
    # Then there is a '.path' service file which watches the github-act-runner binary file for changes. When
    # the file changes (e.g. due to upgrade or remove) it will trigger the third oneshot service, the restarter
    # service.

    local runner_service_name=${pkg_name}.${runner_id}
    local runner_service_file=${runner_service_name}.service
    local restarter_service_file=${runner_service_name}.restarter.service
    local restarter_path_file=${runner_service_name}.path

    # make sure the service units directory exists
    mkdir --parents $systemd_units_dir

    [ ! -f "${systemd_units_dir}${runner_service_file}" ] || error "ASSERT(! -f ${systemd_units_dir}${runner_service_file}) failed"

    echo "\
[Unit]
Description=${pkg_name} '${opts[owner]}/${opts[name]}'
After=network.target

[Service]
ExecStart=${runner_bin_dir}runner run
WorkingDirectory=$runner_dir
KillMode=process
KillSignal=SIGINT
TimeoutStopSec=60min
Restart=always
RestartSec=5s

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
ExecStart=${runner_bin_dir}restart.sh ${runner_service_file}

[Install]
WantedBy=multi-user.target
" > ${systemd_units_dir}${restarter_service_file}

    add_to_err_trap "rm ${systemd_units_dir}${restarter_service_file}"

    [ ! -f "${systemd_units_dir}${restarter_path_file}" ] || error "ASSERT(! -f ${systemd_units_dir}${restarter_path_file}) failed"

    echo "\
[Path]
PathModified=${runner_bin_dir}runner
Unit=${restarter_service_file}

[Install]
WantedBy=multi-user.target
" > ${systemd_units_dir}${restarter_path_file}

    add_to_err_trap "rm ${systemd_units_dir}${restarter_path_file}"

    $systemctl_cmd daemon-reload 

    start_runner_service $runner_id

    echo "runner 'id = ${runner_id}' created"
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

function handle_rm_command {
    # define required options to empty values
    declare -A local opts=( \
        [id]= \
    )

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> add <options>"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                echo "  --id      runner id. See 'ls' command output."
                exit 0
                ;;
            --id)
                shift
                opts[id]=$1
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

    assert_runner_exists ${opts[id]}

    stop_runner_service ${opts[id]}

    local common_prefix=${pkg_name}.${opts[id]}

    rm --force ${systemd_units_dir}${common_prefix}.service
    rm --force ${systemd_units_dir}${common_prefix}.restarter.service
    rm --force ${systemd_units_dir}${common_prefix}.path

    local runner_dir=${runners_dir}${opts[id]}

    rm --recursive --force ${runner_dir}

    $systemctl_cmd daemon-reload

    echo "runner 'id = ${opts[id]}' removed"
}

function handle_stop_command {
    # define required options to empty values
    declare -A local opts=( \
        [id]= \
    )

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> add <options>"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                echo "  --id      runner id. See 'ls' command output."
                exit 0
                ;;
            --id)
                shift
                opts[id]=$1
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

    assert_runner_exists ${opts[id]}

    stop_runner_service ${opts[id]}

    echo "runner 'id = ${opts[id]}' stopped"
}

function handle_start_command {
    # define required options to empty values
    declare -A local opts=( \
        [id]= \
    )

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> add <options>"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                echo "  --id      runner id. See 'ls' command output."
                exit 0
                ;;
            --id)
                shift
                opts[id]=$1
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

    assert_runner_exists ${opts[id]}

    start_runner_service ${opts[id]}

    echo "runner 'id = ${opts[id]}' started"
}

handle_${command}_command $@
