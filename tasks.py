"""Invoke tasks."""

from invoke import Collection, Context, task
from outcome.devkit.invoke import env, tasks
from outcome.read_toml.lib import read_from_file

namespace: Collection = tasks.namespace

github_token: str = env.env.from_config('GITHUB_TOKEN')


@env.env.add
def github_repo_url(e: env.Env) -> str:
    return read_from_file('./pyproject.toml', 'tool.poetry.repository')


@task(name='clear')
def secrets_clear(c: Context):
    """Clear the Github repository secrets."""
    url: str = env.r(github_repo_url)
    c.run(f'poetry run ./bin/secrets.py --url {url} clear')


@task(name='sync')
def secrets_sync(c: Context):
    """Sync the Github repository secrets."""
    url: str = env.r(github_repo_url)
    c.run(f'poetry run ./bin/secrets.py --url {url} sync')


secrets = Collection('secrets')
secrets.add_task(secrets_clear)
secrets.add_task(secrets_sync)

namespace.add_collection(secrets)
