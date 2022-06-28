FROM mozilla/sops

RUN apt-get install -y python3 python3-pip

COPY pyproject.toml setup.cfg setup.py sops_wrapper.py LICENSE ./

RUN python3 -m pip install .

ENTRYPOINT ["/usr/local/bin/sops-wrapper"]
