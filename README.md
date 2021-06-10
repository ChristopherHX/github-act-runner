# github-actions-act-runner

This is a proof of concept runner prototype, which partially implements the azure devops agent protocol to act as self-hosted runner written in go.

# Usage

## Configure

```
go run main.go Configure --url <your github repository url> --name <name of this runner> -l label1,label2 --token <your runner registration token>
```

### `<your github repository url>`:

E.g. `https://github.com/ChristopherHX/github-actions-act-runner` for this repo

### `<name of this runner>`:
E.g. `Test`

### `<your runner registration token>`:

You find the token in `<your github repository url>/settings/actions/runners`, after pressing `Add runner`.

E.g. `AWWWWWWWWWWWWWAWWWWWWAWWWWWWW`

### Labels
Replace label1,label2 with a custom list of runner labels.

## Run

```
go run Run
```