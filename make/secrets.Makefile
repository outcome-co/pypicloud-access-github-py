ifndef MK_SECRETS
MK_SECRETS=1


GITHUB_REPO_URL=$(shell docker run --rm -v $$(pwd):/work/ outcomeco/action-read-toml:latest --path /work/pyproject.toml --key tool.poetry.repository)

secrets-clear:  ## Clear the Github repository secrets
	poetry run ./bin/secrets.py --url $(GITHUB_REPO_URL) clear

secrets-sync:  ## Sync the Github repository secrets
	poetry run ./bin/secrets.py --url $(GITHUB_REPO_URL) sync

endif
