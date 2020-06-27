ifndef MK_DOCS
MK_DOCS=1

# DOCUMENTATION

.PHONY: docs docs-server

docs: export PYTHONPATH = src
docs: ## Generate documentation
	poetry run ./bin/generate_api_docs.py

docs-server: docs ## Run a HTTP server from the /docs directory
	cd docs && \
	python3 -m http.server

endif
