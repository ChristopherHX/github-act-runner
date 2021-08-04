# github-act-runner

[![awesome-runners](https://img.shields.io/badge/listed%20on-awesome--runners-blue.svg)](https://github.com/jonico/awesome-runners)

A reverse engineered github actions compatible self-hosted runner using [act](https://github.com/nektos/act) to execute your workflow steps.
Unlike the [official runner](https://github.com/actions/runner), this works on more systems like freebsd.

# Usage

## Dependencies
|Actions Type|Host|JobContainer (only Linux, Windows, macOS or Openbsd)|
---|---|---
|(composite) run steps|`bash` or explicit shell in your `PATH` (prior running the runner)|Docker (*1), `bash` or explicit shell in your `PATH` (inside your container image)|
|nodejs actions|`node` (*2) in your `PATH` (prior running the runner)|Docker (*1), `node` (*2) in your `PATH` (inside your container image)|
|docker actions|Not available|Docker (*1)|
|service container|Not available|Not available|

(*1) Reachable docker daemon use `DOCKER_HOST` to specify a remote host.

(*2) For best compatibility with existing nodejs actions, please add nodejs in version 12 to your `PATH`, newer nodejs versions might lead to workflow failures.

## usage from prebuilds

Follow the instruction of https://github.com/ChristopherHX/github-act-runner/releases/latest.

## usage from debian repo

### add debian repository
`/etc/apt/sources.list.d/github-act-runner.list` file:
```
deb http://gagis.hopto.org/repo/chrishx/deb all main
```

### import repository public key
```console
curl -sS http://gagis.hopto.org/repo/chrishx/pubkey.gpg | sudo tee -a /etc/apt/trusted.gpg.d/chrishx-github-act-runner.asc
```

### install the runner
```console
sudo apt update
sudo apt install github-act-runner
```

### add new runner
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
