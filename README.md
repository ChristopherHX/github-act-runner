# github-act-runner

[![CI](https://github.com/ChristopherHX/github-act-runner/actions/workflows/build.yml/badge.svg)](https://github.com/ChristopherHX/github-act-runner/actions/workflows/build.yml) [![awesome-runners](https://img.shields.io/badge/listed%20on-awesome--runners-blue.svg)](https://github.com/jonico/awesome-runners)

A reverse engineered github actions compatible self-hosted runner using [act](https://github.com/nektos/act) to execute your workflow steps.
Unlike the [official runner](https://github.com/actions/runner), this works on more systems like freebsd.

# Usage

## Dependencies
|Actions Type|Host|[JobContainer](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#jobsjob_idcontainer) (only Linux, Windows, macOS or Openbsd)|
---|---|---
|([composite](https://docs.github.com/en/actions/creating-actions/creating-a-composite-run-steps-action)) [run steps](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#jobsjob_idstepsrun)|`bash` or [explicit shell](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#custom-shell) in your `PATH` (prior running the runner)|Docker ([*1](#docker-daemon-via-docker_host)), `bash` or [explicit shell](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#custom-shell) in your `PATH` (inside your container image)|
|[nodejs actions](https://docs.github.com/en/actions/creating-actions/creating-a-javascript-action)|`node` ([*2](#nodejs-via-path)) in your `PATH` (prior running the runner)|Docker ([*1](#docker-daemon-via-docker_host)), `node` ([*2](#nodejs-via-path)) in your `PATH` (inside your container image)|
|[docker actions](https://docs.github.com/en/actions/creating-actions/creating-a-docker-container-action)|Not available|Docker ([*1](#docker-daemon-via-docker_host))|
|[service container](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#jobsjob_idservices)|Not available|Not available|
|composite actions with uses|v0.0.10+|v0.0.10+|
|composite actions with if|v0.0.10+|v0.0.10+|
|composite actions with continue-on-error|v0.0.10+|v0.0.10+|

### Docker Daemon via DOCKER_HOST
(*1) Reachable docker daemon use `DOCKER_HOST` to specify a remote host.

### NodeJS via PATH
(*2) For best compatibility with existing nodejs actions, please add nodejs in version 12 to your `PATH`, newer nodejs versions might lead to workflow failures.

## Usage Releases

Follow the instruction of https://github.com/ChristopherHX/github-act-runner/releases/latest.

## Usage Debian Repository

### Add debian repository
`/etc/apt/sources.list.d/github-act-runner.list` file:
```
deb http://gagis.hopto.org/repo/chrishx/deb all main
```

### Import repository public key
```console
curl -sS http://gagis.hopto.org/repo/chrishx/pubkey.gpg | sudo tee -a /etc/apt/trusted.gpg.d/chrishx-github-act-runner.asc
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

## Usage Source

You need at least go 1.16 to use this runner from source.

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
