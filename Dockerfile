FROM mozilla/sops:v3-alpine

RUN apk add --update --no-cache python3 py3-ruamel.yaml && ln -sf python3 /usr/bin/python && python3 -m ensurepip 

COPY pyproject.toml setup.cfg setup.py sops_wrapper.py LICENSE ./

RUN python3 -m pip install .

ENTRYPOINT ["/usr/bin/sops-wrapper"]
