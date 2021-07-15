# github-actions-act-runner

This is a proof of concept runner prototype, which partially implements the azure devops agent protocol to act as self-hosted runner written in go.

# Usage

<details><summary>from debian repo</summary>

## usage from debian repo

### add debian repository
`/etc/apt/sources.list` entry:
```
deb http://gagis.hopto.org/repo/chrishx/<distro> <release> main
```
where
  - `<distro>` is `debian` or `ubuntu`
  - `<release>` is `buster`, etc. in case `<distro>`=`debian`
  - `<release>` is `focal`, etc. in case `<distro>`=`ubuntu`

### import repository public key
```console
curl -sS http://gagis.hopto.org/repo/chrishx/pubkey.gpg | sudo apt-key add -

```

### install the runner
```console
sudo apt update
sudo apt install github-act-runner
```

### configure the runner
```console
github-act-runner configure --url <github-repo-or-org> --name <runner-name> -l <labels> --token <runner-registration-token>
```
where
- `<github-repo-or-org>` - URL to your github repository (e.g. `https://github.com/myname/myrepo`) or organization (e.g. `https://github.com/myorg`)
- `<runner-name>` - choose a name for your runner
- `<labels>` - comma-separated list of labels, e.g. `label1,label2`
- `<runner-registration-token>` - you can find the token in `<your-github-repo-url>/settings/actions/runners`, after pressing `Add runner`

### run the runner
```console
github-act-runner run
```

</details>





<details><summary>from source</summary>

## Usage from source

### Configure

```
go run main.go configure --url <your github repository url> --name <name of this runner> -l label1,label2 --token <your runner registration token>
```

#### `<your github repository url>`:

E.g. `https://github.com/ChristopherHX/github-actions-act-runner` for this repo

#### `<name of this runner>`:
E.g. `Test`

#### `<your runner registration token>`:

You find the token in `<your github repository url>/settings/actions/runners`, after pressing `Add runner`.

E.g. `AWWWWWWWWWWWWWAWWWWWWAWWWWWWW`

#### Labels
Replace `label1,label2` with a custom list of runner labels.

### Run

```
go run main.go run
```
</details>
