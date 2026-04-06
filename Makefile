.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: watch
watch: ## Watch for changes, rebuild and rerun.
	watchexec -r -- "go build . && sudo ./anytunnel"

.PHONY: build-image
build-image: ## Build the Docker image.
	docker build -t github.com/tillycode/anytunnel:latest .

.PHONY: push-image
push-image: ## Push the Docker image to the registry.
	docker push github.com/tillycode/anytunnel:latest
