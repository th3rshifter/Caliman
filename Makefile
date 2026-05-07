SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

IMAGE_NAME ?= caliman
IMAGE_TAG ?= local
APP_HOST ?= 127.0.0.1
APP_PORT ?= 8080
PYTHON ?= python

.PHONY: help \
	install install-dev \
	lint yaml-lint ansible-lint ansible-syntax helm-lint \
	app app-smoke syscheck \
	docker-build docker-run docker-smoke docker-clean \
	frontend-check frontend-serve \
	pipeline-local clean

help:
	@echo "Caliman project commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install          Install runtime Python dependencies"
	@echo "  make install-dev      Install runtime and local tooling dependencies"
	@echo ""
	@echo "Quality gates:"
	@echo "  make lint             Run YAML, Ansible and Helm lint"
	@echo "  make yaml-lint        Run yamllint"
	@echo "  make ansible-lint     Run ansible-lint"
	@echo "  make ansible-syntax   Run ansible-playbook --syntax-check"
	@echo "  make helm-lint        Run helm lint for all charts"
	@echo ""
	@echo "Application:"
	@echo "  make app              Run FastAPI app locally"
	@echo "  make app-smoke        Run local FastAPI smoke test"
	@echo "  make syscheck         Run app/syscheck.py"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build     Build Docker image"
	@echo "  make docker-run       Run Docker container"
	@echo "  make docker-smoke     Build and smoke-test Docker container"
	@echo "  make docker-clean     Remove local smoke-test container"
	@echo ""
	@echo "Frontend:"
	@echo "  make frontend-check   Validate static frontend files"
	@echo "  make frontend-serve   Serve frontend locally on port 3000"
	@echo ""
	@echo "Pipeline:"
	@echo "  make pipeline-local   Run main local checks without GHCR publish"
	@echo "  make clean            Remove local generated files"

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	@echo "✅ Runtime dependencies installed"

install-dev: install
	$(PYTHON) -m pip install yamllint ansible-lint pip-audit psutil rich
	@echo "✅ Local tooling dependencies installed"

lint: yaml-lint ansible-lint ansible-syntax helm-lint
	@echo "✅ Local lint checks passed"

yaml-lint:
	yamllint -c .yamllint.yml .
	@echo "✅ YAML lint passed"

ansible-lint:
	ANSIBLE_CONFIG=ansible/ansible.cfg ansible-lint ansible/playbooks/site.yml
	@echo "✅ Ansible lint passed"

ansible-syntax:
	cd ansible && ansible-playbook playbooks/site.yml --syntax-check
	@echo "✅ Ansible syntax check passed"

helm-lint:
	@if [ ! -d helm ]; then \
		echo "⏭️ No helm directory found, skipping helm lint"; \
		exit 0; \
	fi
	@found=0; \
	for chart in helm/*; do \
		if [ -f "$$chart/Chart.yaml" ]; then \
			found=1; \
			helm lint "$$chart"; \
			echo "✅ Helm lint passed for $$chart"; \
		fi; \
	done; \
	if [ "$$found" -eq 0 ]; then \
		echo "⏭️ No Helm charts found, skipping helm lint"; \
	fi

app:
	$(PYTHON) -m uvicorn app.main:app --host $(APP_HOST) --port $(APP_PORT) --reload

app-smoke:
	@rm -f app.log
	@$(PYTHON) -m uvicorn app.main:app --host $(APP_HOST) --port $(APP_PORT) > app.log 2>&1 & \
	app_pid=$$!; \
	trap 'kill $$app_pid >/dev/null 2>&1 || true' EXIT; \
	for i in $$(seq 1 30); do \
		if curl -fsS http://$(APP_HOST):$(APP_PORT)/health >/dev/null; then \
			curl -fsS http://$(APP_HOST):$(APP_PORT)/ready >/dev/null; \
			curl -fsS http://$(APP_HOST):$(APP_PORT)/ >/dev/null; \
			echo "✅ App smoke test passed"; \
			exit 0; \
		fi; \
		echo "⏳ Waiting for app to start: attempt $$i/30"; \
		sleep 2; \
	done; \
	echo "❌ App smoke test failed"; \
	cat app.log; \
	exit 1

syscheck:
	$(PYTHON) app/syscheck.py
	@echo "✅ Syscheck finished"

docker-build:
	docker build --pull --tag $(IMAGE_NAME):$(IMAGE_TAG) .
	@echo "✅ Docker image built: $(IMAGE_NAME):$(IMAGE_TAG)"

docker-run:
	docker run --rm -p $(APP_PORT):8080 $(IMAGE_NAME):$(IMAGE_TAG)

docker-smoke: docker-build docker-clean
	docker run -d --name caliman-smoke -p $(APP_PORT):8080 $(IMAGE_NAME):$(IMAGE_TAG)
	@for i in $$(seq 1 30); do \
		if curl -fsS http://127.0.0.1:$(APP_PORT)/health >/dev/null; then \
			curl -fsS http://127.0.0.1:$(APP_PORT)/ready >/dev/null; \
			curl -fsS http://127.0.0.1:$(APP_PORT)/ >/dev/null; \
			docker rm -f caliman-smoke >/dev/null; \
			echo "✅ Docker smoke test passed"; \
			exit 0; \
		fi; \
		echo "⏳ Waiting for container to start: attempt $$i/30"; \
		sleep 2; \
	done; \
	echo "❌ Docker smoke test failed"; \
	docker logs caliman-smoke; \
	docker rm -f caliman-smoke >/dev/null; \
	exit 1

docker-clean:
	@docker rm -f caliman-smoke >/dev/null 2>&1 || true
	@echo "✅ Docker smoke container cleaned"

frontend-check:
	test -f frontend/index.html
	test -f frontend/styles.css
	test -f frontend/app.js
	@echo "✅ Frontend static files validated"

frontend-serve:
	cd frontend && $(PYTHON) -m http.server 3000

pipeline-local: lint app-smoke syscheck frontend-check docker-smoke
	@echo "✅ Local pipeline completed"

clean: docker-clean
	rm -f app.log
	rm -rf public
	@echo "✅ Local generated files removed"
