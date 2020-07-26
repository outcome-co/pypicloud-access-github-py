import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import pytest
from outcome.pypicloud_access_github import Poetry

from .github_fixture import github_scenario  # noqa: WPS300

_UNDEFINED_VALUE = '__UNDEFINED'


def read_from_env(var: str, default=_UNDEFINED_VALUE):
    if var not in os.environ:
        if default != _UNDEFINED_VALUE:
            return default
        raise Exception(f'You need to provide the {var} environment variable to run the integration tests')
    return os.environ[var]


@pytest.fixture(scope='session')
def github_token():
    return read_from_env('PYPICLOUD_ACCESS_GITHUB_TEST_TOKEN')


@pytest.fixture(scope='session')
def github_organization():
    return read_from_env('PYPICLOUD_ACCESS_GITHUB_TEST_ORGANIZATION')


@pytest.fixture(scope='session')
def github_admin_username():
    return read_from_env('PYPICLOUD_ACCESS_GITHUB_TEST_ADMIN_USERNAME')


@pytest.fixture(scope='session')
def github_admin_token():
    return read_from_env('PYPICLOUD_ACCESS_GITHUB_TEST_ADMIN_TOKEN')


@pytest.fixture(scope='session')
def github_member_username():
    return read_from_env('PYPICLOUD_ACCESS_GITHUB_TEST_MEMBER_USERNAME')


@pytest.fixture(scope='session')
def github_member_token():
    return read_from_env('PYPICLOUD_ACCESS_GITHUB_TEST_MEMBER_TOKEN')


@pytest.fixture(scope='session')
def github_nonmember_username():
    return read_from_env('PYPICLOUD_ACCESS_GITHUB_TEST_NONMEMBER_USERNAME')


@pytest.fixture(scope='session')
def github_nonmember_token():
    return read_from_env('PYPICLOUD_ACCESS_GITHUB_TEST_NONMEMBER_TOKEN')


@pytest.fixture(scope='session')
def additional_admins():
    admins = read_from_env('PYPICLOUD_ACCESS_GITHUB_TEST_ADDITIONAL_ADMINS', None)

    if admins is None:
        return []

    return list(map(lambda a: a.strip(), admins.split(',')))


@pytest.fixture(scope='session')
def session_id():
    session_key = 'pypi'
    session_hash = hashlib.sha1(str(datetime.now()).encode('utf-8')).hexdigest()  # noqa: S303
    short_hash = session_hash[:8]
    return f'{session_key}-{short_hash}'


@pytest.fixture(scope='session')
def user_map(github_member_username: str, github_admin_username: str):
    return {
        '$MEMBER_USER': github_member_username,
        '$ADMIN_USER': github_admin_username,
    }


@pytest.fixture(scope='session')
def unknown_member():
    return 'unknown-member'


@pytest.fixture
def settings(github_token: str, github_organization: str):
    return {
        'auth.otc.github.token': github_token,
        'auth.otc.github.organization': github_organization,
    }


@pytest.fixture
def github_access(settings):
    return Poetry(**Poetry.configure(settings))


@pytest.fixture
def invalid_github_access(settings):
    bad_settings = {'auth.otc.github.token': 'bad token'}
    settings.update(**bad_settings)
    return Poetry(**Poetry.configure(settings))


def scenario_file(name: str) -> Path:
    return Path(Path(__file__).parent, 'scenarios', f'{name}.json')


@pytest.fixture(scope='session')
def scenario_context(github_token: str, github_organization: str, user_map: Dict[str, str], session_id: str):
    return {
        'token': github_token,
        'organization': github_organization,
        'user_map': user_map,
        'session_id': session_id,
    }


@pytest.fixture(scope='session')
def read_permission():
    return {'read'}


@pytest.fixture(scope='session')
def write_permission():
    return {'write'}


@pytest.fixture(scope='session')
def read_write_permission(read_permission, write_permission):
    return read_permission | write_permission


@pytest.fixture(scope='class')
def multiple_empty_repos_scenario(scenario_context: Dict[str, Any]):
    with github_scenario(path=scenario_file('multiple_empty_repos'), **scenario_context) as scenario:
        yield scenario


@pytest.fixture(scope='class')
def multiple_teams_scenario(scenario_context: Dict[str, Any]):
    with github_scenario(path=scenario_file('multiple_teams'), **scenario_context) as scenario:
        yield scenario


@pytest.fixture(scope='class')
def user_permissions_scenario(scenario_context: Dict[str, Any]):
    with github_scenario(path=scenario_file('user_permissions'), **scenario_context) as scenario:
        yield scenario


@pytest.fixture(scope='class')
def team_permissions_scenario(scenario_context: Dict[str, Any]):
    with github_scenario(path=scenario_file('team_permissions'), **scenario_context) as scenario:
        yield scenario


@pytest.fixture(scope='class')
def user_data_scenario(scenario_context: Dict[str, Any]):
    with github_scenario(path=scenario_file('user_data'), **scenario_context) as scenario:
        yield scenario


@pytest.fixture(scope='class')
def packages_scenario(scenario_context: Dict[str, Any]):
    with github_scenario(path=scenario_file('packages'), **scenario_context) as scenario:
        yield scenario
