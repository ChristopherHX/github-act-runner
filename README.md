# github-act-runner

This is a proof of concept runner prototype, which partially implements the azure devops agent protocol to act as self-hosted runner written in go.

# Usage

<details><summary>from debian repo</summary>

## usage from debian repo

### add debian repository
`/etc/apt/sources.list` entry:
```
deb http://gagis.hopto.org/repo/chrishx/deb all main
```

### import repository public key
```console
curl -sS http://gagis.hopto.org/repo/chrishx/pubkey.gpg | sudo apt-key add -
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
- `<runner-registration-token>` - you can find the token in `<your-github-repo-url>/settings/actions/runners`, after pressing `Add runner`

The new runner will be registered and started as background service.

See help:
```console
github-act-runner --help
```
For more info about managing runners.

</details>





<details><summary>from source</summary>

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
go run main.go configure --url <github-repo-or-org-or-enterprise> --name <name of this runner> -l label1,label2 --token <runner registration token>
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
go run main.go run
```
</details>
