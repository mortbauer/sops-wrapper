# sops-wrapper

This is a simple wrapper around [sops](https://github.com/mozilla/sops), which
does use the `.sops.yaml` to determine the files which need to be encrypted or
decrypted.

## Installation

Install with pip:

```
python -m pip install sosp-wrapper
```
## Usage

run it with `sops-wrapper encrypt --dry-run` or `sops-wrapper decrypt --dry-run`, 
remove the `--dry-run` flag to make it actually happen.

### run docker build

This is a command to put complex ci/cd logic back to local makefiles and use
just very simple ci/cd things, it uses Dockerfiles to run things platform and
env independent.

For example create a file `Dockerfile-Test` with the contents:
```
FROM debian:bullseye-slim as esp-idf

RUN echo 1
RUN --mount=type=secret,id=MYSECRET echo "AAAAAAAAA $(cat /run/secrets/MYSECRET)"
```

create the sops config `.sops.yaml` with the contents:
```
creation_rules:
  - path_regex: testenv.json
    age: age134ua239eacs8dk5lrys5g7wtfa90tv9y9cnzw984wmkwfjaslu7qd9luys
```

and create a sops encrypted secrets file "testenv.json" with the command `sops testenv.json` and the contents:
```
{
	"MYSECRET": "Welcome to SOPS! Edit this file as you please!"
}
```

example cmd:
```
sops-wrapper dockerbuild -s testenv.json -f Dockerfile-Test
```

which will create a simple docker image, however you hopefully get the idea that you can whatever you want here, you can also pass additional args to docker e.g:
```
sops-wrapper dockerbuild -s testenv.json -f Dockerfile-Test --progress=plain
```
