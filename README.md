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
