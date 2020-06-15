"""An access backend for pypicloud that uses Github as a source of authority.

Users authenticate against the pypi registry with their login and a personal access token.

The registry is tied to a specific Github Organization. Only users that are members of the
Organization will be able to access the registry.

Packages are automatically detected in repos (only packages with pyproject.toml files are considered,
the package name is read from the TOML file), and the permissions are infered from Github permissions
associated with the users.

Github Teams are used to represent pypi groups.

The access backend needs to be configured with an access token that has read-access to the entire Organization
(or at least the Teams, Members, and Repository scopes).
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from cachetools import TTLCache
from github import ContentFile, Github, GithubObject, Organization, Repository
from github.GithubException import GithubException
from outcome.pypicloud_access_github import poetry_reader
from pypicloud.access.base import IAccessBackend
from pyramid.settings import aslist

_cache_size = 100
_cache_ttl = 120

_poetry = 'pyproject.toml:poetry'

_permissions_map = {
    'pull': ['read'],
    'push': ['write', 'read'],
    'admin': ['write', 'read']
}


class GithubAccess(IAccessBackend):  # noqa: WPS214, WPS230
    def __init__(  # noqa: WPS211
        self,
        github_token: str,
        github_organization: str,
        package_repo_file_types: List[str],
        package_repo_pattern: Optional[str] = None,
        package_repo_visibility: Optional[str] = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.github_token = github_token
        self.github_organization_name = github_organization
        self.github_client = Github(github_token)

        self.package_repo_file_types = package_repo_file_types
        self.package_repo_pattern = package_repo_pattern
        self.package_repo_visibility = package_repo_visibility

        self.cache = TTLCache(_cache_size, _cache_ttl)

    @property
    def organization(self) -> Organization.Organization:
        if 'organization' not in self.cache:
            self.cache['organization'] = self.github_client.get_organization(self.github_organization_name)
        return self.cache['organization']

    def get_repositories(self, visibility: Optional[str] = None) -> List[Repository.Repository]:
        if visibility not in {'public', 'private'}:
            visibility = GithubObject.NotSet
            cache_key = 'repos:all'
        else:
            cache_key = f'repos:{visibility}'

        if cache_key not in self.cache:
            self.cache[cache_key] = list(self.organization.get_repos(type=visibility))

        return self.cache[cache_key]

    def get_package_name_from_file_type(
        self,
        package_file: ContentFile.ContentFile,
        package_repo_file_type: str,
    ) -> Optional[str]:
        if package_repo_file_type == _poetry:
            return poetry_reader.get_package_name(package_file)

        return None

    def get_package_from_repo(self, repository: Repository.Repository) -> Optional[Tuple[str, Repository.Repository]]:
        """Attempt to retrieve the package name from a repository.

        For the provided file types, the method will attempt to retrieve the file from the repository and extract
        the package name from the file.

        Currently, the method only supports `pyproject.toml:poetry`, where the package name is stored in `tools.poetry.name`
        inside a `pyproject.toml` file.

        Args:
            repository (Repository.Repository): The repository from which to attempt to infer the package name.

        Returns:
            Optional[Tuple[str, Repository.Repository]]: If successful, returns an tuple with (package_name, repository),
                otherwise returns None.
        """
        for package_repo_file_type in self.package_repo_file_types:
            try:
                file_name, _ = package_repo_file_type.split(':')
                package_file = repository.get_contents(file_name)
            except GithubException:
                pass
            else:
                package_name = self.get_package_name_from_file_type(package_file, package_repo_file_type)
                if package_name:
                    return (package_name, repository)

        return None

    @property
    def packages(self) -> Dict[str, Repository.Repository]:
        """Returns the list of available packages from the GitHub Organization.

        Packages are determined by examining each repository and attempting to retrieve one
        of the file that corresponds to one of the `package_repo_file_types`, from which the package
        name can be inferred.

        If a repository does not contain one of the `package_repo_file_types`, or the package name cannot
        be inferred from the file, the repository is ignored.

        The set of repositories to consider can be filtered using `package_repo_pattern` which will be
        interpreted as a regular expression on the repository name. The value can be omitted if no
        filtering should occur.

        The set of repositories can also be restricted by visibility type, either `public` or `private`.
        The value can be omitted if no filtering should occur.

        Returns:
            Dict[str, Repository.Repository]: A dict of package names and their associated repositories.
        """
        if 'packages' not in self.cache:
            repos_filtered_by_visibility = self.get_repositories(self.package_repo_visibility)

            if self.package_repo_pattern:
                repos_filtered_by_name = [r for r in repos_filtered_by_visibility if re.search(self.package_repo_pattern, r.name)]
            else:
                repos_filtered_by_name = repos_filtered_by_visibility

            self.cache['packages'] = dict(filter(None, (self.get_package_from_repo(r) for r in repos_filtered_by_name)))

        return self.cache['packages']

    @classmethod
    def configure(cls, settings) -> Dict[str, Any]:
        return {
            'default_read': aslist(settings.get('pypi.default_read', ['authenticated'])),
            'default_write': aslist(settings.get('pypi.default_write', [])),
            'github_token': settings.get('otc.access.github.token'),
            'github_organization': settings.get('otc.access.github.organization'),
            'package_repo_file_types': aslist(settings.get('otc.access.github.package_repo_file_types', [_poetry])),
            'package_repo_pattern': settings.get('otc.access.github.package_repo_pattern', None),
            'package_repo_visibility': settings.get('otc.access.github.package_repo_visibility', None),
        }

    def is_valid_token_for_username(self, username: str, token: str) -> bool:
        """Check that the token is associated with the username.

        Args:
            username (str): The username.
            token (str): The token.

        Returns:
            bool: True if the token is associated with the username.
        """
        # We create a new client, specifically to verify the user's
        # credentials
        try:
            user_client = Github(token)
            user = user_client.get_user()

            # Ensure the username matches the token
            return user and user.login == username
        except GithubException:
            return False

    def verify_user(self, username: str, password: str) -> bool:
        """Check the login credentials of a user.

        Args:
            username (str): The username.
            password (str): The password.

        Returns:
            bool: True if user credentials are valid, false otherwise.
        """
        # The password is the user's PAT
        token = password

        if not self.is_valid_token_for_username(username, token):
            return False

        # Check organisation membership
        user = self.github_client.get_user(username)

        if not user or not self.organization.has_in_members(user):
            return False

        return True

    def groups(self, username: Optional[str] = None) -> List[str]:
        """Get a list of all groups.

        If a username is specified, get all groups to which the user belongs.

        Args:
            username (str, optional): The username.

        Returns:
            List[str]: The list of group names.
        """
        user = None

        if username:
            try:
                user = self.github_client.get_user(username)
            except GithubException:
                return []

            if not user or not self.organization.has_in_members(user):
                return []

        teams = self.organization.get_teams()

        if user:
            teams = filter(lambda t: t.has_in_members(user), teams)

        return map(lambda t: t.name, teams)

    def group_members(self, group: str) -> List[str]:
        """Get a list of users that belong to a group.

        Args:
            group (str): The name of the group.

        Returns:
            List[str]: The list usernames of the members of the group.
        """
        teams = self.organization.get_teams()
        team = next((t for t in teams if t.name == group), None)

        if not team:
            return []

        return list(map(lambda u: u.login, team.get_members()))

    def is_admin(self, username: str) -> bool:
        """Check if the user is an admin.

        Args:
            username (str): The username to check.

        Returns:
            bool: True if the user is an admin.
        """
        org_admins = self.organization.get_members(role='admin')
        return any(True for admin in org_admins if admin.login == username)

    def group_permissions(self, package: str) -> Dict[str, List[str]]:
        """Get a mapping of all groups to their permissions on a package.

        Args:
            package (str): The name of a python package

        Returns:
            dict: Mapping of group name to a list of permissions (which can contain 'read' and/or 'write')
        """
        packages = self.packages

        if package not in packages:
            return {}

        repository = packages[package]

        return {
            team.name: _permissions_map[team.permission]
            for team in repository.get_teams()
        }

    def user_permissions(self, package: str) -> Dict[str, List[str]]:
        """
        Get a mapping of all users to their permissions for a package
        Parameters
        ----------
        package : str
            The name of a python package
        Returns
        -------
        permissions : dict
            Mapping of username to a list of permissions (which can contain
            'read' and/or 'write')
        """
        raise NotImplementedError

    def user_package_permissions(self, username: str) -> List[Dict[str, List[str]]]:
        """
        Get a list of all packages that a user has permissions on
        Parameters
        ----------
        username : str
        Returns
        -------
        packages : list
            List of dicts. Each dict contains 'package' (str) and 'permissions'
            (list)
        """
        raise NotImplementedError

    def group_package_permissions(self, group: str) -> List[Dict[str, List[str]]]:
        """
        Get a list of all packages that a group has permissions on
        Parameters
        ----------
        group : str
        Returns
        -------
        packages : list
            List of dicts. Each dict contains 'package' (str) and 'permissions'
            (list)
        """
        raise NotImplementedError

    def user_data(self, username: Optional[str] = None):
        """
        Get a list of all users or data for a single user
        For Mutable backends, this MUST exclude all pending users
        Returns
        -------
        users : list
            Each user is a dict with a 'username' str, and 'admin' bool
        user : dict
            If a username is passed in, instead return one user with the fields
            above plus a 'groups' list.
        """
        if username:
            user = self.github_client.get_user(username)


    def check_health(self) -> Tuple[bool, str]:
        """Check the health of the access backend.

        This ensures that the provided access token can access the specified organization, and has
        the correct permissions.

        Returns:
            Tuple[bool, str]: Tuple that describes the health status and provides an optional status message.
        """
        try:
            self.organization.get_teams()
            self.organization.get_repos()
            return (True, '')
        except Exception as ex:
            return (False, str(ex))
