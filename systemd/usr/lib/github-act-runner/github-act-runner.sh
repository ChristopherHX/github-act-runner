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
journalctl_cmd="journalctl --quiet"
if $is_root; then
    echo "running as root"
    journalctl_cmd="${journalctl_cmd} --unit"
    systemd_units_dir=/etc/systemd/system/
else
    user="$(id --user --name)"
    echo "running as user '$user'"
    systemctl_cmd="${systemctl_cmd} --user"
    journalctl_cmd="${journalctl_cmd} --user --user-unit"
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

function warning {
    local message=$1

    $is_term && printf "\t\e[1;35mWARNING\e[0m: $message\n" || printf "\tWARNING: $message\n"
}

cur_err_trap=
function add_to_err_trap {
    local cmd="$1;"

    # apply trap commands in reverse order, added last - executed first
    cur_err_trap="$cmd ${cur_err_trap}"
    trap "${cur_err_trap}" ERR
}

declare -A commands=( \
        [ls]="list registered runners" \
        [new]="register new runner" \
        [rm]="remove registered runner" \
        [stop]="stop runner service" \
        [start]="start runner service" \
        [restart]="restart runner service" \
        [log]="show logs of the runner service" \
        [configure]="configure a runner instance in your cwd" \
        [run]="run a runner instance in your cwd" \
        [worker]="run a worker instance without configuration called by github-act-runner" \
    )

while [[ $# > 0 ]] ; do
    case $1 in
        --help)
            echo "usage:"
            echo "  $(basename $0) [<options>] <command> [--help] [<command-options>] [...]"
            echo ""
            echo "options:"
            echo "  --help     show this help text and do nothing."
            echo "  --version  show the runner version"
            echo ""
            echo "commands:"
            for i in "${!commands[@]}"; do {
                printf "  %-8s %s\n" $i "${commands[$i]}"
            } done
            exit 0
            ;;
        --version)
            $runner_bin --version
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
        [url]= \
        [name]= \
        [token]= \
    )

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> new <options>"
                echo ""
                echo "options:"
                echo "  --help          show this help text and do nothing."
                echo "  --url           github repo or organization URL (e.g. 'https://github.com/user/repo' or 'https://github.com/organization')."
                echo "  --name          new runner name."
                echo "  --labels        comma separated list of runner labels, e.g. 'label1,label1,label3'. Optional."
                echo "  --token         github runner registration token."
                echo "  --runnergroup   runner group name. Optional."
                exit 0
                ;;
            --url)
                shift
                opts[url]=$1
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
        local service_wanted_by="default.target"

        # check if lingering is enabled
        if [ -z "$(loginctl show-user $user | grep 'Linger=yes')" ]; then
            warning "Lingering is not enabled for user '$user'. Lingering is needed to make user services start at boot and to prevent them from being stopped when user logs out. Enable lingering using command 'loginctl enable-linger'."
        fi
    else
        local service_wanted_by="multi-user.target"
    fi

    mkdir --parents $runners_dir

    local runner_id=${opts[name]}

    local runner_dir="${runners_dir}${runner_id}"
    if [ -d "$runner_dir" ]; then
        echo "runner 'id = ${runner_id}' already exists"

        local number_suffix=1

        while [ -d "${runner_dir}.${number_suffix}" ]; do
            number_suffix=$((number_suffix+1))
        done

        runner_id="${runner_id}.${number_suffix}"
        runner_dir="${runners_dir}${runner_id}"

        echo "will create runner 'id = ${runner_id}'"
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

    (
        cd $runner_dir &&
        if ! $runner_bin configure --unattended --url ${opts[url]} --name ${opts[name]} --token ${opts[token]} $labels $runnergroup; then
            error "failed creating runner on github"
        fi
        # echo "\$? = $?"
    )

    # in case anything fails with setting up services below, we remove the registered runner from github
    add_to_err_trap "(cd $runner_dir; $runner_bin remove --unattended --url ${opts[url]} --token ${opts[token]} > /dev/null)"

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
Description=${pkg_name} '${runner_id}'
After=network.target

[Service]
ExecStart=${runner_bin} run
WorkingDirectory=$runner_dir
KillMode=process
KillSignal=SIGINT
TimeoutStopSec=60min
Restart=always
RestartSec=5s

[Install]
WantedBy=${service_wanted_by}
" > ${systemd_units_dir}${runner_service_file}

    add_to_err_trap "rm ${systemd_units_dir}${runner_service_file}"

    [ ! -f "${systemd_units_dir}${restarter_service_file}" ] || error "ASSERT(! -f ${systemd_units_dir}${restarter_service_file}) failed"

    echo "\
[Unit]
Description=${pkg_name} '${runner_id}' restarter
After=network.target

[Service]
Type=oneshot
ExecStart=${runner_bin_dir}restart.sh ${runner_service_file}

[Install]
WantedBy=${service_wanted_by}
" > ${systemd_units_dir}${restarter_service_file}

    add_to_err_trap "rm ${systemd_units_dir}${restarter_service_file}"

    [ ! -f "${systemd_units_dir}${restarter_path_file}" ] || error "ASSERT(! -f ${systemd_units_dir}${restarter_path_file}) failed"

    echo "\
[Path]
PathModified=${runner_bin}
Unit=${restarter_service_file}

[Install]
WantedBy=${service_wanted_by}
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

    # define required options to empty values
    declare -A local opts=( \
    )

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> ls [<options>]"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                exit 0
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
        # check if lingering is enabled
        if [ -z "$(loginctl show-user $user | grep 'Linger=yes')" ]; then
            warning "Lingering is disabled for user '$user'. Enable lingering using command 'loginctl enable-linger'."
        fi
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
    )

    local runner_id=

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> rm <runner-id> [<options>]"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                exit 0
                ;;
            *)
                if [ -z "$runner_id" ]; then
                    runner_id=$1
                else
                    error "unknown option: $1"
                fi
                ;;
        esac
        [[ $# > 0 ]] && shift;
    done

    [ ! -z "$runner_id" ] || error "runner id is not given"

    for opt in ${!opts[@]}; do
        [ ! -z "${opts[$opt]}" ] || error "missing option: --$opt"
    done

    assert_runner_exists $runner_id

    stop_runner_service $runner_id

    local common_prefix=${pkg_name}.$runner_id

    rm --force ${systemd_units_dir}${common_prefix}.service
    rm --force ${systemd_units_dir}${common_prefix}.restarter.service
    rm --force ${systemd_units_dir}${common_prefix}.path

    local runner_dir=${runners_dir}$runner_id

    rm --recursive --force ${runner_dir}

    $systemctl_cmd daemon-reload

    echo "runner 'id = $runner_id' removed"
}

function handle_stop_command {
    # define required options to empty values
    declare -A local opts=( \
    )

    local runner_id=

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> stop <runner-id> [<options>]"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                exit 0
                ;;
            *)
                if [ -z "$runner_id" ]; then
                    runner_id=$1
                else
                    error "unknown option: $1"
                fi
                ;;
        esac
        [[ $# > 0 ]] && shift;
    done

    [ ! -z "$runner_id" ] || error "runner id is not given"

    for opt in ${!opts[@]}; do
        [ ! -z "${opts[$opt]}" ] || error "missing option: --$opt"
    done

    assert_runner_exists $runner_id

    stop_runner_service $runner_id

    echo "runner 'id = $runner_id' stopped"
}

function handle_start_command {
    # define required options to empty values
    declare -A local opts=( \
    )

    local runner_id=

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> start <runner-id> [<options>]"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                exit 0
                ;;
            *)
                if [ -z "$runner_id" ]; then
                    runner_id=$1
                else
                    error "unknown option: $1"
                fi
                ;;
        esac
        [[ $# > 0 ]] && shift;
    done

    [ ! -z "$runner_id" ] || error "runner id is not given"

    for opt in ${!opts[@]}; do
        [ ! -z "${opts[$opt]}" ] || error "missing option: --$opt"
    done

    assert_runner_exists $runner_id

    start_runner_service $runner_id

    echo "runner 'id = $runner_id' started"
}

function handle_restart_command {
    # define required options to empty values
    declare -A local opts=( \
    )

    local runner_id=

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> restart <runner-id> [<options>]"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                exit 0
                ;;
            *)
                if [ -z "$runner_id" ]; then
                    runner_id=$1
                else
                    error "unknown option: $1"
                fi
                ;;
        esac
        [[ $# > 0 ]] && shift;
    done

    [ ! -z "$runner_id" ] || error "runner id is not given"

    for opt in ${!opts[@]}; do
        [ ! -z "${opts[$opt]}" ] || error "missing option: --$opt"
    done

    assert_runner_exists $runner_id

    stop_runner_service $runner_id
    start_runner_service $runner_id

    echo "runner 'id = $runner_id' restarted"
}

function handle_log_command {
    # define required options to empty values
    declare -A local opts=( \
    )

    local runner_id=

    local follow=

    while [[ $# > 0 ]] ; do
        case $1 in
            --help)
                echo "usage:"
                echo "	$(basename $0) <...> log <runner-id> [<options>]"
                echo ""
                echo "options:"
                echo "  --help    show this help text and do nothing."
                echo "  --follow  watch for new log lines and show them as they appear."
                exit 0
                ;;
            --follow)
                follow=true
                ;;
            *)
                if [ -z "$runner_id" ]; then
                    runner_id=$1
                else
                    error "unknown option: $1"
                fi
                ;;
        esac
        [[ $# > 0 ]] && shift;
    done

    [ ! -z "$runner_id" ] || error "runner id is not given"

    for opt in ${!opts[@]}; do
        [ ! -z "${opts[$opt]}" ] || error "missing option: --$opt"
    done

    assert_runner_exists $runner_id

    if [ ! -z "$follow" ]; then
        follow="--follow"
    fi

    if ! $journalctl_cmd ${pkg_name}.${runner_id}.service $follow; then
        error "journalctl failed. In case it is due to insufficient permissions, add 'Storage=persistent' to '/etc/systemd/journal.conf' and restart 'systemd-journald' service."
    fi
}

function handle_configure_command {
    "${runner_bin}" configure "$@"
}

function handle_run_command {
    trap 'kill -INT $PID' INT
    trap 'kill -TERM $PID' TERM
    "${runner_bin}" run "$@" &
    PID="$!"
    wait "$PID" # wait for SIGINT (exit after finishing the running job) / SIGTERM (cancels running job) or normal exit
    wait "$PID" # wait for job or SIGINT (cancels running job)
    wait "$PID" # wait for graceful exit
    exitcode="$?"
    exit "$exitcode"
}

function handle_worker_command {
    "${runner_bin}" worker "$@"
}

handle_${command}_command "$@"
