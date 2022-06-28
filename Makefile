.PHONY: build publish


build:
	python -m build

publish:
	twine upload dist/*

image:
	docker buildx build --tag mortbauer/sops-wrapper .

publish-image:
	docker push mortbauer/sops-wrapper
