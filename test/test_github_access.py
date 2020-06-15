import os
from typing import Set
from unittest.mock import Mock, PropertyMock, patch

import pytest
from github import Github, GithubException, Organization
from outcome.devkit.test_helpers import skip_for_integration, skip_for_unit
from outcome.pypicloud_access_github import GithubAccess

team_a = 'Team A'
team_b = 'Team B'


def read_from_env(var: str):
    if var not in os.environ:
        raise Exception(f'You need to provide the {var} environment variable to run the integration tests')
    return os.environ[var]


@pytest.fixture(scope='session')
def all_groups():
    return {team_a, team_b}


@pytest.fixture(scope='session')
def group_members(github_member_username):
    return {
        'not_empty': (team_a, [github_member_username]),
        'empty': (team_b, []),
    }


@pytest.fixture(scope='session')
def groups_for_member():
    return {team_a}


@pytest.fixture(scope='session')
def empty_group(group_members):
    return group_members['empty']


@pytest.fixture(scope='session')
def group_with_members(group_members):
    return group_members['not_empty']


@pytest.fixture(scope='session')
def unknown_member():
    # Definitely an unknown user, as usernames can't start with '-'
    return '-bad-username'


@pytest.fixture(scope='session')
def unknown_group():
    return '-invalid-group'


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
def settings(github_token: str, github_organization: str):

    return {
        'otc.access.github.token': github_token,
        'otc.access.github.organization': github_organization,
    }


@pytest.fixture
def github_access(settings):
    return GithubAccess(**GithubAccess.configure(settings))


@pytest.fixture
@patch('outcome.pypicloud_access_github.github_access.Github', autospec=True)
def github_access_with_mock_api(mocked_github_client, settings):
    return GithubAccess(**GithubAccess.configure(settings))


@skip_for_integration
class TestHealthCheck:
    def test_has_correct_scope(self, github_access_with_mock_api: GithubAccess):
        health, _ = github_access_with_mock_api.check_health()
        assert health

    def test_has_incorrect_scope(self, github_access_with_mock_api: GithubAccess):

        mock_organization = Mock(spec_set=Organization.Organization)
        mock_organization.get_repos.side_effect = GithubException(status='400', data='')

        github_access_with_mock_api.github_client.get_organization.return_value = mock_organization
        health, _ = github_access_with_mock_api.check_health()
        assert not health


@skip_for_unit
class TestVerifyUser:
    def test_valid_login(self, github_access: GithubAccess, github_member_username, github_member_token):
        assert github_access.verify_user(github_member_username, github_member_token)

    def test_invalid(self, github_access: GithubAccess, unknown_member):
        assert not github_access.verify_user(unknown_member, '-')

    def test_invalid_username_for_valid_token(self, github_access: GithubAccess, github_member_token, unknown_member):
        assert not github_access.verify_user(unknown_member, github_member_token)

    def test_valid_login_not_member_of_org(self, github_access: GithubAccess, github_nonmember_username, github_nonmember_token):
        user_client = Github(github_nonmember_username, github_nonmember_token)

        assert user_client.get_user().login == github_nonmember_username
        assert not github_access.verify_user(github_nonmember_username, github_nonmember_token)


@skip_for_unit
class TestGroups:
    def test_all_groups(self, github_access: GithubAccess, all_groups: Set[str]):
        assert set(github_access.groups()) == all_groups

    def test_groups_for_non_member(self, github_access: GithubAccess, github_nonmember_username):
        assert github_access.groups(github_nonmember_username) == []

    def test_groups_for_unknown_member(self, github_access: GithubAccess, unknown_member):
        assert github_access.groups(unknown_member) == []

    def test_groups_for_member_of_one_group(self, github_access: GithubAccess, github_member_username, groups_for_member):
        assert set(github_access.groups(github_member_username)) == groups_for_member


@skip_for_unit
class TestGroupMembers:
    def test_get_empty_group(self, github_access: GithubAccess, empty_group):
        group_name, _ = empty_group
        assert github_access.group_members(group_name) == []

    def test_get_group_with_members(self, github_access: GithubAccess, group_with_members):
        group_name, members = group_with_members
        assert set(github_access.group_members(group_name)) == set(members)

    def test_invalid_group(self, github_access: GithubAccess, unknown_group):
        assert github_access.group_members(unknown_group) == []


@skip_for_unit
class TestIsAdmin:
    def test_member_non_admin(self, github_access: GithubAccess, github_member_username):
        assert not github_access.is_admin(github_member_username)

    def test_non_member_non_admin(self, github_access: GithubAccess, github_nonmember_username):
        assert not github_access.is_admin(github_nonmember_username)

    def test_admin_member(self, github_access: GithubAccess, github_admin_username):
        assert github_access.is_admin(github_admin_username)


@pytest.fixture(scope='session')
def public_packages():
    return {'public-sandbox-repository-package'}


@pytest.fixture(scope='session')
def private_packages():
    return {'private-sandbox-repository-package', 'private-sandbox-repository-2-package'}


@pytest.fixture(scope='session')
def all_packages(public_packages, private_packages):
    return public_packages | private_packages


@skip_for_unit
class TestPackages:
    def test_get_all_poetry_packages(self, github_access: GithubAccess, all_packages):
        packages = github_access.packages
        assert set(packages.keys()) == all_packages

    def test_get_public_poetry_packages(self, github_access: GithubAccess, public_packages):
        github_access.package_repo_visibility = 'public'
        packages = github_access.packages
        assert set(packages.keys()) == public_packages

    def test_get_private_poetry_packages(self, github_access: GithubAccess, private_packages):
        github_access.package_repo_visibility = 'private'
        packages = github_access.packages
        assert set(packages.keys()) == private_packages

    def test_get_packages_filtered_by_name(self, github_access: GithubAccess, private_packages):
        github_access.package_repo_pattern = '^private'
        packages = github_access.packages
        assert set(packages.keys()) == private_packages


@skip_for_integration
class TestCache:

    def test_package_cache(self, github_access: GithubAccess):
        with patch.object(github_access, 'get_repositories') as patched_get_repositories:
            patched_get_repositories.return_value = []

            assert github_access.packages == {}
            assert github_access.packages == {}

            assert len(patched_get_repositories.call_args_list) == 1

    def test_repository_visibility_cache(self, github_access: GithubAccess):  # noqa: WPS218
        with patch(
            'outcome.pypicloud_access_github.GithubAccess.organization', new_callable=PropertyMock,
        ) as patched_organization:
            mocked_organization = Mock(spec_set=Organization.Organization)

            patched_organization.return_value = mocked_organization

            public_repos_ret_val = ['public_repos']
            mocked_organization.get_repos.return_value = public_repos_ret_val

            assert github_access.get_repositories('public') == public_repos_ret_val
            assert github_access.get_repositories('public') == public_repos_ret_val
            assert len(mocked_organization.get_repos.call_args_list) == 1

            mocked_organization.get_repos.reset_mock()

            private_repos_ret_val = ['private_repos']
            mocked_organization.get_repos.return_value = private_repos_ret_val

            assert github_access.get_repositories('private') == private_repos_ret_val
            assert github_access.get_repositories('private') == private_repos_ret_val
            assert len(mocked_organization.get_repos.call_args_list) == 1

            mocked_organization.get_repos.reset_mock()

            all_repos_ret_val = ['all']
            mocked_organization.get_repos.return_value = all_repos_ret_val

            assert github_access.get_repositories() == all_repos_ret_val
            assert github_access.get_repositories() == all_repos_ret_val
            assert len(mocked_organization.get_repos.call_args_list) == 1

            mocked_organization.get_repos.reset_mock()

            assert github_access.get_repositories('public') == public_repos_ret_val
            assert github_access.get_repositories('private') == private_repos_ret_val
            assert github_access.get_repositories() == all_repos_ret_val

            assert not mocked_organization.get_repos.called


@skip_for_integration
class TestGetPackageName:
    def test_unknown_package_file_type(self, github_access: GithubAccess):
        assert github_access.get_package_name_from_file_type(None, 'unknown') is None


def package_permissions_raw():
    return {
        'private-sandbox-repository-package': {'Team A': {'read'}, 'Team B': {'read', 'write'}},
        'public-sandbox-repository-package': {'Team A': {'read', 'write'}, 'Team B': {'read'}},
        'private-sandbox-repository-2-package': {'Team B': {'read', 'write'}},
    }


@pytest.fixture(scope='session', params=package_permissions_raw().items())
def package_permissions(request):
    return request.param


@skip_for_unit
class TestGroupPermissions:
    def test_basic_read_write(self, github_access: GithubAccess, package_permissions):
        package, perms = package_permissions
        permissions = github_access.group_permissions(package)

        assert perms == {g: set(p) for g, p in permissions.items()}

    def test_unknown_package(self, github_access: GithubAccess):
        assert github_access.group_permissions('unknown') == {}
