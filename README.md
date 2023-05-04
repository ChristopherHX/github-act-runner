# github-act-runner

[![CI](https://github.com/ChristopherHX/github-act-runner/actions/workflows/build.yml/badge.svg)](https://github.com/ChristopherHX/github-act-runner/actions/workflows/build.yml) [![awesome-runners](https://img.shields.io/badge/listed%20on-awesome--runners-blue.svg)](https://github.com/jonico/awesome-runners)

A reverse engineered github actions compatible self-hosted runner using [nektos/act](https://github.com/nektos/act) to execute your workflow steps.
Unlike the official [actions/runner](https://github.com/actions/runner), this works on more systems like freebsd.

# Usage

## Dependencies
|Actions Type|Host|[JobContainer](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#jobsjob_idcontainer) (only Linux, Windows, macOS)|
---|---|---
|([composite](https://docs.github.com/en/actions/creating-actions/creating-a-composite-run-steps-action)) [run steps](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#jobsjob_idstepsrun)|`bash` (preferred), `sh` or [explicit shell](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#custom-shell) in your `PATH` (prior running the runner). On windows are `pwsh` (preferred) and `powershell` the default shells instead of `bash` or `sh`|Docker ([*1](#docker-daemon-via-docker_host)), `sh` or [explicit shell](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#custom-shell) in your `PATH` (inside your container image)|
|[nodejs actions](https://docs.github.com/en/actions/creating-actions/creating-a-javascript-action)|`node` ([*2](#nodejs-via-path)) in your `PATH` (prior running the runner)|Docker ([*1](#docker-daemon-via-docker_host)), `node` ([*2](#nodejs-via-path)) in your `PATH` (inside your container image)|
|[docker actions](https://docs.github.com/en/actions/creating-actions/creating-a-docker-container-action)|Not available|Docker ([*1](#docker-daemon-via-docker_host))|
|[service container](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#jobsjob_idservices)|Not available|Not available|
|composite actions with uses|v0.1.0|v0.1.0|
|composite actions with if|v0.1.0|v0.1.0|
|composite actions with continue-on-error|v0.1.0|v0.1.0|

### Docker Daemon via DOCKER_HOST
(*1) Reachable docker daemon use `DOCKER_HOST` to specify a remote host.

### NodeJS via PATH
(*2) For best compatibility with existing nodejs actions, please add nodejs in version 12 to your `PATH`, newer nodejs versions might lead to workflow failures.

## Usage for github releases

Follow the instruction of https://github.com/ChristopherHX/github-act-runner/releases/latest.

## Usage for debian repository

### Add debian repository
`/etc/apt/sources.list.d/github-act-runner.list` file:
```
deb https://gagis.hopto.org/repo/chrishx/deb all main
```

### Import repository public key
```console
curl -sS https://gagis.hopto.org/repo/chrishx/pubkey.gpg | sudo tee -a /etc/apt/trusted.gpg.d/chrishx-github-act-runner.asc
```

### Install the runner
```console
sudo apt update
sudo apt install github-act-runner
```

### Add new runner
```console
github-act-runner new --url <url> --name <runner-name> --labels <labels> --token <runner-registration-token>
```
where
- `<url>` - github repository (e.g. `https://github.com/user/repo`), organization (e.g. `https://github.com/organization`) or enterprise URL
- `<runner-name>` - choose a name for your runner
- `<labels>` - comma-separated list of labels, e.g. `label1,label2`. Optional.
- [`<runner-registration-token>`](#runner-registration-token)

The new runner will be registered and started as background service.

See help:
```console
github-act-runner --help
```
For more info about managing runners.

## Usage from source

You need at least go 1.18 to use this runner from source.

### Getting Source
```
git clone https://github.com/ChristopherHX/github-act-runner.git --recursive
```

### Update Source
```
git pull
git submodule update
```

### Configure

```
go run . configure --url <github-repo-or-org-or-enterprise> --name <name of this runner> -l label1,label2 --token <runner registration token>
```

#### `<github-repo-or-org-or-enterprise>`

E.g. `https://github.com/ChristopherHX/github-act-runner` for this repo

#### `<name of this runner>`
E.g. `Test`

#### `<runner registration token>`

||You find the token in|
---|---
|Repository|`<github-repo>/settings/actions/runners/new`|
|Organization|`<github-url>/organizations/<github-org-name>/settings/actions/runners/new`|
|Enterprise|In action runner settings of your enterprise|

E.g. `AWWWWWWWWWWWWWAWWWWWWAWWWWWWW`

#### Labels
Replace `label1,label2` with a custom list of runner labels.

### Run

```
go run . run
```

# Breaking changes in 0.6.0

- `runner.os` changed from `darwin` to `macOS`
- `runner.arch` changed from `x86_64` to `x64`
- `runner.arch` changed from `386` to `x86`
- `runner.arch` changed from `aarch64` to `arm64`
- `shell` parameter might behave differently
- based on `nektos/act@d77991c95ab6eb357b9327163ac9ceca3d04ce9b`
- the docker client has been removed from openbsd builds
- windows runners now prefers `pwsh` and `powershell` as default shell, while running directly on windows
- all other systems now fallback to `sh` if bash is not found
- now requires go 1.18 to compile
- `protocol.JobLogger` moved to `"protocol/logger"` package

# Known Limitations
- ~~This runner ignores pre and post steps of javascript actions~~ Is now working in 0.6.0
- ~~[actions/cache](https://github.com/actions/cache) is incompatible and won't be able to **save your cache**~~
  - ~~Using https://github.com/actions/toolkit/tree/main/packages/cache directly should allow you to save your cache~~
  Is now working in 0.6.0, including hashfiles
- ~~You won't be able to run steps after a failure without using `continue-on-error: true`~~ Implemented since v0.2.0 via nektos/act contribution ( https://github.com/nektos/act/commit/1891c72ab158508e36009d16b24913fa5836422b )
- ~~The expression interpreter of this runner doesn't always behave like you would expect and you might see errors or other expressions which shouldn't work are working here ( based on javascript, not on actions/runner )~~ v0.2.0 uses rhysd/actionlint instead with much better compatibility https://github.com/nektos/act/pull/908
- ~~`add-mask` command not implemented~~ Is now working in 0.6.0
- ~~Running steps after cancellation~~ Is now working in 0.6.0
- ~~steps.timeout-minutes not implemented~~ Is now working in 0.6.0
- Service Container are not implemented
- Step Summaries are not implemented (only file command is provided)
- Annotations are not implemented
- Problem Matcher are not implemented
- Expressions in `with` and `env` (also applies to workflow and job env blocks) keys / directly assign to a mapping expression are not implemented
- Secret masking may leak more secrets than the one of actions/runner
- Job Outputs are sent regardless if they would leak secret data to non secret storage
- You need to provide the `node` program yourself in all containers / host configurations
- You need to manually update the runner
- Most issues of https://github.com/nektos/act/issues applies to this runner as well

# How does it work?
This runner implements the same protocol as the [actions/runner](https://github.com/actions/runner) in a different way, as such it can be used as a self-hosted runner exactly like the official one. To get this working, I initially built an actions service replacement [ChristopherHX/runner.server](https://github.com/ChristopherHX/runner.server) for the official [actions/runner](https://github.com/actions/runner). My own actions service allowed me to implement the base protocol for this runner and debug how the protocol is serializeing and parsing json messages, while still being incompatible with github. After testing against github, the first thing happend was loosing the ability to run any github action workflows on my test repository. My invalid attempts to register a custom runner caused unrecoverable Internal Server Errors on githubs side, I decided to delete this test repository. After some work everything worked and finally it is safe to register this runner against github. To execute steps this runner translates the github actions job request to be compatible with a modified version of [nektos/act](https://github.com/nektos/act) ( [ChristopherHX/act](https://github.com/ChristopherHX/act) ), which adds a local task runner without the need for docker and increased platform support, also the log output of act gets redirected to github for live logs and storing log files.

# Does this runner work without github?
Yes, you can use this runner together with [ChristopherHX/runner.server](https://github.com/ChristopherHX/runner.server) locally on your PC without depending on compatibility with github. Also CI tests for this runner are using [ChristopherHX/runner.server](https://github.com/ChristopherHX/runner.server), this avoids requiring a PAT for github to run tests and enshures that you are always able to run it locally without github.