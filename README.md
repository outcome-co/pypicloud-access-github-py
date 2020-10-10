# pypicloud-access-github

![ci-badge](https://github.com/outcome-co/pypicloud-access-github-py/workflows/Checks/badge.svg) ![version-badge](https://img.shields.io/badge/version-1.2.0-brightgreen)

This package provides a Github-based authentication backend for [pypicloud](https://pypicloud.readthedocs.io/en/latest/).

The package binds the PyPICloud instance to a GitHub Organization, and uses GitHub users, teams, and permissions to provide authentication and access control.

## Usage

### Installation

You can install the package directly from pypi, alongside your `pypicloud` installation.

```sh
poetry add outcome-pypicloud-access-github
```

Or, if you want to use `memcache` for caching.

```sh
poetry add outcome-pypicloud-access-github[memcache]
```

### Configuration

You need to configure PyPICloud to use the auth backend, in the `server.ini`:

```ini
pypi.auth = outcome.pypicloud_access_github.Poetry

auth.otc.github.organization = <INSERT YOUR ORGANIZATION NAME HERE>
auth.otc.github.token = <INSERT YOUR TOKEN HERE>
```

You can see a sample [here](./samples/server.ini).

#### Caching

Retrieving the authentication information from GitHub can be a relatively slow process, depending on the size of your organization. The plugin implements an internal TTL cache using [dogpile.cache](https://dogpilecache.sqlalchemy.org/en/latest/) to avoid hitting GitHub on each request.

By default the cache backend is an in-memory cache, that is not shared across threads or processes. You can configure the cache to use a `memcache` instance that will be shared amongst threads/processes.

```ini
auth.otc.github.cache.backend = memory  # Use the memory backend
auth.otc.github.cache.expiration = 300  # Expire the cache items after 300s
```

For `memcache`:

```ini
auth.otc.github.cache.backend = memcache  # Use the memcache backend
auth.otc.github.cache.expiration = 300  # Expire the cache items after 300s
auth.otc.github.cache.memcache.url = 127.0.0.1:11211  # The server:port of your memcache instance
```

#### Options

The full list of configuration options:

| Option                               |  Default          | Description                                                                           |
| ------------------------------------ | ----------------- | ------------------------------------------------------------------------------------- |
| `auth.otc.github.token`              | None              |  The Github Token used to query Github for the auth information                       |
| `auth.otc.github.organization`       | None              | The Github Organization name to use as a directory                                    |
| `auth.otc.github.repo_pattern`       | `.*`              | A pattern that will be interpreted as a regular expression to filter repository names |
| `auth.otc.github.repo_include_list`  | `[]`              | A list of repository names to include. Names not in the list will be excluded         |
| `auth.otc.github.repo_exclude_list`  | `[]`              | A list of repository names to exclude. Names in the list will be excluded             |
| `auth.otc.github.cache.backend`      | `memory`          | The cache backend to use, can be `memory` or `memcache`                               |
| `auth.otc.github.cache.expiration`   |  `300`            | The TTL for each cache key                                                            |
| `auth.otc.github.cache.memcache.url` | `127.0.0.1:11211` | The url of the memcache server                                                        |

#### Github Token

You can create a Personal Access Token from your [Developer Settings](https://github.com/settings/tokens/). The token must have `repo`, `admin:org`, and `read:user` permissions.

### Publishing & Pulling Packages

You can use your standard tools to publish to the repository (see here for [Poetry](https://python-poetry.org/docs/libraries/#publishing-to-a-private-repository)). The username will be the GitHub username of the user, and the token will be a Personal Access Token assigned to that user. The token only requires `read:user` scopes as it is only used to verify the identity of the user.

### How GitHub concepts are mapped to PyPICloud

#### Authorization & Authentication

The GitHub ACL elements are mapped pretty intuitively onto PyPICloud ACL elements.

- Users login with their username and PAT (the backend ensures that the username matches the token)
- Permissions are defined by the GitHub roles applied either on the Team, Repository, or Organization levels

The permissions are mapped as follows:

| GitHub Role |  PyPI Permissions |
| ----------- | ----------------- |
| `admin`     | `read`, `write`   |
| `maintain`  | `read`, `write`   |
| `triage`    | `read`            |
| `read`      | `read`            |
| `write`     | `read`, `write`   |

#### Packages

The backend considers each repository to be a potential package (the backend isn't designed for monorepos). The backend will attempt to retrieve package information from the repository. Currently, the backend only supports [Poetry](https://python-poetry.org) packages, using `pyproject.toml`, but it is easy to support other file formats by creating a new subclass of the `outcome.pypicloud_access_github.access.Access` class (see [poetry.py](./src/outcome/pypicloud_access_github/poetry.py) as an example.)

For example, the repository for this library contains a `pyproject.toml` with the following:

```toml
[tool.poetry]
name = "outcome-pypicloud-access-github"
version = "0.1.0"
description = "An Github-based access backend for pypicloud."
```

The backend will read this file and determine that the package is named `outcome-pypicloud-access-github`.

## Development

Remember to run `./pre-commit.sh` when you clone the repository.

### Testing

The testing is mainly made up of integration tests, read the [testing README](./test/README.md) for more details.
