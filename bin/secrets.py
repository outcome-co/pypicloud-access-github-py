#! /usr/bin/env python
"""Simple secrets management to allow for Github Actions integration tests.

Values to synchronise are taken either from the .env file, or from the environment variables.
"""

import json
import os
import re
from base64 import b64encode
from typing import Dict, List, Tuple

import click
import requests
from dotenv import find_dotenv, load_dotenv
from nacl import encoding, public
from pydantic import BaseModel

# Load .env file
load_dotenv(find_dotenv())


_github_url_pattern = r'^https://github.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/?$'


def parse_url(url: str) -> Tuple[str, str]:
    match = re.match(_github_url_pattern, url)
    if not match:
        raise click.ClickException('Invalid Github URL')

    return (match.group('owner'), match.group('repo'))


@click.group()
@click.option('--url', required=True, help='The Github repository URL')
@click.pass_context
def main(ctx: click.Context, url: str) -> None:
    """You need to provide a Github PAT via the GITHUB_TOKEN environment variable.

    Args:
        ctx (click.Context): The click context.
        url (str): The repository url.
    """
    org, repo = parse_url(url)

    ctx.obj['organization'] = org
    ctx.obj['repository'] = repo


@main.command()
@click.pass_context
def clear(ctx: click.Context) -> None:
    """Clear all of the secrets from the repository.

    Args:
        ctx (click.Context): The click context.
    """
    token = require_env_var('GITHUB_TOKEN')

    client = SecretClient(token=token, organization=ctx.obj['organization'])
    client.clear_secrets(ctx.obj['repository'])


@main.command()
@click.pass_context
def sync(ctx) -> None:
    """Update the secrets on the repo with the local values.

    Args:
        ctx (click.Context): The click context.
    """
    env_vars = [
        'PYPICLOUD_ACCESS_GITHUB_TEST_MEMBER_USERNAME',
        'PYPICLOUD_ACCESS_GITHUB_TEST_MEMBER_TOKEN',
        'PYPICLOUD_ACCESS_GITHUB_TEST_NONMEMBER_USERNAME',
        'PYPICLOUD_ACCESS_GITHUB_TEST_NONMEMBER_TOKEN',
        'PYPICLOUD_ACCESS_GITHUB_TEST_ADMIN_USERNAME',
        'PYPICLOUD_ACCESS_GITHUB_TEST_ADMIN_TOKEN',
        'PYPICLOUD_ACCESS_GITHUB_TEST_ORGANIZATION',
        'PYPICLOUD_ACCESS_GITHUB_TEST_TOKEN',
        'PYPICLOUD_ACCESS_GITHUB_TEST_ADDITIONAL_ADMINS',
    ]

    require_env_vars(env_vars)

    token = require_env_var('GITHUB_TOKEN')
    client = SecretClient(token=token, organization=ctx.obj['organization'])

    for var in env_vars:
        client.create(ctx.obj['repository'], var, os.environ.get(var))


# Github REST Models
class Secret(BaseModel):
    """Represents a secret.

    https://developer.github.com/v3/actions/secrets/#list-repository-secrets
    """

    name: str


class Secrets(BaseModel):
    """Represents a list of secrets.

    https://developer.github.com/v3/actions/secrets/#list-repository-secrets
    """

    secrets: List[Secret]


class PublicKey(BaseModel):
    """Represents a Github Secrets Repository Public Key.

    https://developer.github.com/v3/actions/secrets/#get-a-repository-public-key
    """

    key: str
    key_id: str

    def encrypt(self, secret_value: str) -> str:
        """Encrypt a value with the public key.

        Args:
            secret_value (str): The value to encrypt.

        Returns:
            str: The encrypted value.
        """
        public_key = public.PublicKey(self.key.encode('utf-8'), encoding.Base64Encoder())
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(secret_value.encode('utf-8'))
        return b64encode(encrypted).decode('utf-8')


class Client:
    """Minimal REST client for Github.

    We could use PyGithub, but they don't currently support the Secrets API.
    """

    github_endpoint = 'https://api.github.com'

    def __init__(self, token: str, organization: str):
        self.token = token
        self.organization = organization

    def get(self, url, **kwargs):
        return self.execute('GET', url, **kwargs)

    def put(self, url, **kwargs):
        return self.execute('PUT', url, **kwargs)

    def delete(self, url, **kwargs):
        return self.execute('DELETE', url, **kwargs)

    def execute(self, method, url, **kwargs):
        auth_header = f'Bearer {self.token}'

        response = requests.request(method, url, headers={'Authorization': auth_header}, **kwargs)
        response.raise_for_status()

        return response

    def build_url(self, template, **kwargs):
        url = template.format(owner=self.organization, **kwargs)
        return '{host}{url}'.format(host=self.github_endpoint, url=url)


class SecretClient(Client):
    """Minimal REST client for Github Secrets."""

    def create(self, repository: str, name: str, value: str) -> None:
        """Create or update a secret.

        Args:
            repository (str): The repository that contains the secret.
            name (str): The name of the secret.
            value (str): The secret value (unencrypted).
        """
        key = self.get_public_key(repository)
        encrypted_secret = key.encrypt(value)

        url = self.build_url('/repos/{owner}/{repo}/actions/secrets/{name}', repo=repository, name=name)

        self.put(url, data=json.dumps({'encrypted_value': encrypted_secret, 'key_id': key.key_id}))

        click.echo(f'Created secret: {url}')

    def get_public_key(self, repository: str) -> PublicKey:
        """Retrieve the public key from a repository.

        Args:
            repository (str): The repository name.

        Returns:
            PublicKey: The public key object.
        """
        url = self.build_url('/repos/{owner}/{repo}/actions/secrets/public-key', repo=repository)
        return PublicKey(**self.get(url).json())

    def clear_secrets(self, repository: str):
        """Remove all the secrets from a repository.

        Args:
            repository (str): The repository name.
        """
        for secret in self.get_secrets(repository).secrets:
            self.delete_secret(repository, secret.name)

    def delete_secret(self, repository: str, name: str):
        """Remove a secret from a repository.

        Args:
            repository (str): The repository name.
            name (str): The name of the secret to remove.
        """
        url = self.build_url('/repos/{owner}/{repo}/actions/secrets/{name}', repo=repository, name=name)
        self.delete(url)
        click.echo(f'Deleted secret: {url}')

    def get_secrets(self, repository: str) -> Secrets:
        """Retrieve all the secrets from a repository.

        Args:
            repository (str): The repository name.

        Returns:
            Secrets: The list of secrets.
        """
        # This doesn't handle pagination
        url = self.build_url('/repos/{owner}/{repo}/actions/secrets', repo=repository)
        return Secrets(**self.get(url).json())


_UNDEFINED_VALUE = '_UNDEFINED_VALUE'


def require_env_vars(env_vars: List[str]) -> Dict[str, str]:
    return {ev: require_env_var(ev) for ev in env_vars}


def require_env_var(env_var: str) -> str:
    value = os.environ.get(env_var, _UNDEFINED_VALUE)
    if value == _UNDEFINED_VALUE:
        raise click.ClickException(f'{env_var} environment variable is missing!')
    return value


if __name__ == '__main__':
    main(obj={})
