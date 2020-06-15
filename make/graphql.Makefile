GRAPHQL_SCHEMA_DIR = src/outcome/pypicloud_access_github

graphql-generate-schema: ## Generates the GitHub GraphQL Schema file
	python3 -m sgqlc.introspection --exclude-deprecated --exclude-description -H "Authorization: bearer ${GITHUB_TOKEN}" https://api.github.com/graphql $(GRAPHQL_SCHEMA_DIR)/schema.json
	sgqlc-codegen $(GRAPHQL_SCHEMA_DIR)/schema.json $(GRAPHQL_SCHEMA_DIR)/graphql_schema.py
