.PHONY: build publish image

IMAGE_NAME:=mortbauer/sops
TAG:=latest

build:
	python -m build

publish-wheel:
	twine upload dist/*

image:
	docker buildx build --tag ${IMAGE_NAME}:${TAG} --load .

publish:
	docker push ${IMAGE_NAME}:${TAG}
