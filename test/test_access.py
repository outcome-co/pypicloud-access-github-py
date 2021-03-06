import re
from typing import Sequence, Set

from flaky import flaky
from github import Github
from outcome.devkit.test_helpers import skip_for_unit
from outcome.pypicloud_access_github import Access
from outcome.pypicloud_access_github.graphql.schemas.models.repository import DefaultRepositoryPermissionField

from .scenario import RepositoryRole, Scenario


def convert_role_to_permission(role: RepositoryRole) -> DefaultRepositoryPermissionField:  # noqa: WPS212,WPS231
    if role == RepositoryRole.admin:  # noqa: WPS223
        return DefaultRepositoryPermissionField.admin
    elif role == RepositoryRole.maintain:
        return DefaultRepositoryPermissionField.write
    elif role == RepositoryRole.write:
        return DefaultRepositoryPermissionField.write
    elif role == RepositoryRole.triage:
        return DefaultRepositoryPermissionField.read
    elif role == RepositoryRole.read:
        return DefaultRepositoryPermissionField.read
    return DefaultRepositoryPermissionField.none


@skip_for_unit
@flaky(max_runs=3)
class TestHealthCheck:
    def test_has_correct_scope(self, github_access: Access):
        health, _ = github_access.check_health()
        assert health

    def test_has_incorrect_scope(self, invalid_github_access: Access):
        health, _ = invalid_github_access.check_health()
        assert not health


@skip_for_unit
@flaky(max_runs=3)
class TestVerifyUser:
    def test_valid_login(self, github_access: Access, github_member_username: str, github_member_token: str):
        assert github_access.verify_user(github_member_username, github_member_token)

    def test_valid_login_valid_token_unassociated(
        self, github_access: Access, github_member_username: str, github_nonmember_token: str,
    ):
        assert not github_access.verify_user(github_member_username, github_nonmember_token)

    def test_invalid(self, github_access: Access, unknown_member: str):
        assert not github_access.verify_user(unknown_member, 'invalid token')

    def test_invalid_username_for_valid_token(self, github_access: Access, github_member_token: str, unknown_member: str):
        assert not github_access.verify_user(unknown_member, github_member_token)

    def test_valid_login_not_member_of_org(
        self, github_access: Access, github_nonmember_username: str, github_nonmember_token: str,
    ):
        user_client = Github(github_nonmember_username, github_nonmember_token)

        assert user_client.get_user().login == github_nonmember_username
        assert not github_access.verify_user(github_nonmember_username, github_nonmember_token)


@skip_for_unit
@flaky(max_runs=3)
class TestGroups:
    def test_all_groups(self, github_access: Access, multiple_teams_scenario: Scenario):
        assert multiple_teams_scenario.team_names.issubset(github_access.groups())

    def test_groups_for_non_member(
        self, github_access: Access, multiple_teams_scenario: Scenario, github_nonmember_username: str,
    ):
        assert github_access.groups(github_nonmember_username) == []

    def test_groups_for_unknown_member(self, github_access: Access, multiple_teams_scenario: Scenario, unknown_member: str):
        assert github_access.groups(unknown_member) == []

    def test_groups_for_member_of_one_group(
        self, github_access: Access, multiple_teams_scenario: Scenario, github_member_username: str,
    ):
        groups = {t.name for t in multiple_teams_scenario.teams if github_member_username in t.members}
        assert groups.issubset(set(github_access.groups(github_member_username)))

    def test_get_empty_group(self, github_access: Access, multiple_teams_scenario: Scenario):
        group_name = next((t.name for t in multiple_teams_scenario.teams if not t.members))
        assert github_access.group_members(group_name) == []

    def test_get_group_with_members(self, github_access: Access, multiple_teams_scenario: Scenario):
        team = next((t for t in multiple_teams_scenario.teams if t.members))
        assert set(github_access.group_members(team.name)) == set(team.members)

    def test_invalid_group(self, github_access: Access, multiple_teams_scenario: Scenario):
        assert github_access.group_members('unknown-group') == []


@skip_for_unit
@flaky(max_runs=3)
class TestIsAdmin:
    def test_member_non_admin(self, github_access: Access, github_member_username: str):
        assert not github_access.is_admin(github_member_username)

    def test_non_member_non_admin(self, github_access: Access, github_nonmember_username: str):
        assert not github_access.is_admin(github_nonmember_username)

    def test_admin_member(self, github_access: Access, github_admin_username: str):
        assert github_access.is_admin(github_admin_username)


@skip_for_unit
@flaky(max_runs=3)
class TestUserPermissions:
    def test_admin_has_all_access_to_all_packages(
        self,
        github_access: Access,
        user_permissions_scenario: Scenario,
        github_admin_username: str,
        read_write_permission: Set[str],
    ):
        for repo in user_permissions_scenario.repositories:
            repo_perms = github_access.user_permissions(repo.meta['package'])
            assert set(repo_perms[github_admin_username]) == read_write_permission

    def test_member_has_read_access_to_all_packages(
        self, github_access: Access, user_permissions_scenario: Scenario, github_member_username: str, read_permission: Set[str],
    ):
        # We need to ensure that the scenario has a repo
        # where the `github_member_username` doesn't have explicit access
        has_repo = False

        for repo in user_permissions_scenario.repositories:

            role = next((r for r in repo.collaborators if r.name == github_member_username), None)
            # Skip repos with explicit permissions on the user
            if role:
                continue

            has_repo = True
            repo_perms = github_access.user_permissions(repo.meta['package'])

            assert set(repo_perms[github_member_username]) == read_permission

        assert has_repo

    def test_user_permissions_for_unknown_package(self, github_access: Access, user_permissions_scenario: Scenario):
        repo_perms = github_access.user_permissions('unknown-package')
        assert repo_perms == {}

    def test_all_packages_for_user(
        self, github_access: Access, user_permissions_scenario: Scenario, github_member_username: str, read_permission: Set[str],
    ):
        user_package_permissions = github_access.user_package_permissions(github_member_username)
        package_perm_map = {p['package']: p['permissions'] for p in user_package_permissions}

        for repo in user_permissions_scenario.repositories:
            # Skip non-package repos
            if 'package' not in repo.meta:
                continue

            # Get the role for the user, if there is one
            role = next((r for r in repo.collaborators if r.name == github_member_username), None)

            if role:
                assert github_access.convert_permission(convert_role_to_permission(role.role)) == set(
                    package_perm_map[repo.meta['package']],
                )
            # If there's no specific permissions, there should be default permissions
            else:
                assert set(package_perm_map[repo.meta['package']]) == read_permission


@skip_for_unit
@flaky(max_runs=3)
class TestGroupPermissions:
    def get_team_with_permission_on_repo(self, scenario: Scenario, permission: str, repo: str):
        for team in scenario.teams:
            for r in team.repositories:
                if r.name == repo and r.role.value == permission:
                    return team.name

        raise ValueError(f'No such team with {permission} on {repo}')

    def perm_check(self, github_access: Access, scenario: Scenario, perm_name: str, permissions: Set[str]):
        repo = scenario.repositories[0]
        package = repo.meta['package']
        repo_perms = github_access.group_permissions(package)
        team = self.get_team_with_permission_on_repo(scenario, perm_name, repo.name)
        assert set(repo_perms[team]) == permissions

    def test_admin_has_read_write(
        self, github_access: Access, team_permissions_scenario: Scenario, read_write_permission: Set[str],
    ):
        self.perm_check(github_access, team_permissions_scenario, 'admin', read_write_permission)

    def test_maintain_has_read_write(
        self, github_access: Access, team_permissions_scenario: Scenario, read_write_permission: Set[str],
    ):
        self.perm_check(github_access, team_permissions_scenario, 'maintain', read_write_permission)

    def test_write_has_read_write(
        self, github_access: Access, team_permissions_scenario: Scenario, read_write_permission: Set[str],
    ):
        self.perm_check(github_access, team_permissions_scenario, 'write', read_write_permission)

    def test_triage_has_read(self, github_access: Access, team_permissions_scenario: Scenario, read_permission: Set[str]):
        self.perm_check(github_access, team_permissions_scenario, 'triage', read_permission)

    def test_read_has_read(self, github_access: Access, team_permissions_scenario: Scenario, read_permission: Set[str]):
        self.perm_check(github_access, team_permissions_scenario, 'read', read_permission)

    def test_group_package_permissions(self, github_access: Access, team_permissions_scenario: Scenario):
        package_repo_map = {r.meta['package']: r.name for r in team_permissions_scenario.repositories if 'package' in r.meta}

        for team in team_permissions_scenario.teams:
            group_package_perms = github_access.group_package_permissions(team.name)
            team_repo_perms = {r.name: r.role for r in team.repositories}

            for package_perms in group_package_perms:
                repo = package_repo_map[package_perms['package']]
                assert github_access.convert_permission(convert_role_to_permission(team_repo_perms[repo])) == set(
                    package_perms['permissions'],
                )


@skip_for_unit
@flaky(max_runs=3)
class TestUserData:
    def test_user_admin_status(
        self,
        github_access: Access,
        user_data_scenario: Scenario,
        github_admin_username: str,
        github_member_username: str,
        additional_admins: Sequence[str],
    ):
        user_data = github_access.user_data()
        user_data_dict = {u['username']: u['admin'] for u in user_data}

        # Exclude any meta-admins
        assert len(user_data) - len(additional_admins) == len(user_data_scenario.users)

        # Check admin statuses
        assert user_data_dict[github_admin_username]
        assert not user_data_dict[github_member_username]

    def test_user_groups(self, github_access: Access, user_data_scenario: Scenario):
        for user in user_data_scenario.users:
            teams = {t.name for t in user_data_scenario.teams if user.name in t.members}
            user_data = github_access.user_data(user.name)

            groups = user_data['groups']

            assert groups is not None
            assert user_data['username'] == user.name
            assert teams.issubset(set(groups))


@skip_for_unit
@flaky(max_runs=3)
class TestPackages:
    def test_get_all_poetry_packages(self, github_access: Access, packages_scenario: Scenario):
        scenario_packages = {r.meta['package'] for r in packages_scenario.repositories if 'package' in r.meta}
        packages = github_access.package_names()
        assert scenario_packages.issubset(set(packages.keys()))

    def test_exclude_packages(self, github_access: Access, packages_scenario: Scenario):
        scenario_packages = [(r.meta['package'], r.name) for r in packages_scenario.repositories if 'package' in r.meta]

        # Ensure we've got at least two packages
        assert len(scenario_packages) > 1
        assert github_access.repo_exclude_list is not None

        excluded_package_name, excluded_repo = scenario_packages.pop()
        github_access.repo_exclude_list.append(excluded_repo)

        packages = github_access.package_names()

        assert excluded_package_name not in packages

    def test_include_packages(self, github_access: Access, packages_scenario: Scenario):
        scenario_packages = [(r.meta['package'], r.name) for r in packages_scenario.repositories if 'package' in r.meta]

        # Ensure we've got at least two packages
        assert len(scenario_packages) > 1
        assert github_access.repo_include_list is not None

        included_package_name, included_repo = scenario_packages.pop()
        github_access.repo_include_list.append(included_repo)

        packages = github_access.package_names()

        assert included_package_name in packages

    def test_package_pattern(self, github_access: Access, packages_scenario: Scenario):
        scenario_packages = [(r.meta['package'], r.name) for r in packages_scenario.repositories if 'package' in r.meta]

        # Ensure we've got at least two packages
        assert len(scenario_packages) > 1

        # Match repos ending with '-2'
        test_pattern = '-2$'

        filtered_scenario_packages = list(filter((lambda p: re.match(test_pattern, p[1]) is not None), scenario_packages))
        excluded_scenario_packages = {p[0] for p in scenario_packages if p not in filtered_scenario_packages}
        github_access.repo_pattern = test_pattern

        packages = github_access.package_names()

        assert {p for p, _ in filtered_scenario_packages}.issubset(set(packages.keys()))
        assert set(packages.keys()) & excluded_scenario_packages == set()
