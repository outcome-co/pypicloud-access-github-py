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

import abc
import logging
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from outcome.pypicloud_access_github.graphql import schema
from outcome.pypicloud_access_github.graphql.client import Client, Operation
from outcome.utils import cache
from pypicloud.access.base import ONE_WEEK, IAccessBackend
from pyramid.settings import aslist

LOG = logging.getLogger(__name__)

# Build a new dogpile.cache cache region
# we'll configure it later when the Access.configure method is called
cache_region = cache.get_cache_region()


_read_permission = 'read'
_write_permission = 'write'


class GithubRoles(Enum):
    admin = 'admin'
    maintain = 'maintain'
    write = 'write'
    triage = 'triage'
    read = 'read'


# Mapping from Github roles to pypi permissions
_permissions_map = {
    GithubRoles.admin.value: {_read_permission, _write_permission},
    GithubRoles.maintain.value: {_read_permission, _write_permission},
    GithubRoles.write.value: {_read_permission, _write_permission},
    GithubRoles.triage.value: {_read_permission},
    GithubRoles.read.value: {_read_permission},
}

_teams_key = 'teams'
_users_key = 'users'


UserRole = Tuple[str, str]
TeamMemberMap = Dict[str, List[UserRole]]
User = Dict[str, Union[str, bool, List[str]]]
UserWithGroups = User
EntityPermissions = Dict[str, Set[str]]
RepositoryPermissions = Dict[str, EntityPermissions]


class Access(abc.ABC, IAccessBackend):  # pragma: only-covered-in-integration-tests; # noqa: WPS214
    def __init__(  # noqa: WPS211, too many arguments
        self,
        request=None,
        default_read=None,
        default_write=None,
        disallow_fallback=(),
        cache_update=None,
        pwd_context=None,
        token_expiration=ONE_WEEK,
        signing_key=None,
        token: str = None,
        organization: str = None,
        repo_pattern: Optional[str] = None,
        repo_include_list: Optional[str] = None,
        repo_exclude_list: Optional[str] = None,
    ) -> None:

        super().__init__(
            request, default_read, default_write, disallow_fallback, cache_update, pwd_context, token_expiration, signing_key,
        )

        self.organization_name = organization

        self.client = Client(token)

        self.repo_pattern = repo_pattern
        self.repo_include_list = repo_include_list
        self.repo_exclude_list = repo_exclude_list

    def organization_operation(self) -> Tuple[Operation, schema.Organization]:
        op = self.client.operation()
        org = op.organization(login=self.organization_name)

        return (op, org)

    @abc.abstractmethod
    def get_package_name(self, package_file_content: str) -> Optional[str]:
        ...

    @property
    @abc.abstractmethod
    def package_file_name(self) -> str:
        ...

    @staticmethod
    def convert_permission(github_role: str) -> Set[str]:
        """Convert a Github role ('admin', 'triage', etc. ) to read/write permissions.

        Args:
            github_role (str): The Github role.

        Returns:
            Set[str]: The set of permissions (either 'read' or 'write', or both)
        """
        return _permissions_map[github_role.lower()]

    @cache_region.cache_on_arguments()
    def package_files(self) -> Dict[str, Optional[str]]:
        """Retrieve the map of repositories and the contents of the package files.

        All of the repositories in the organization will be listed, if the repository
        doesn't contain a package file the value associated with the key will be
        `None`.

        If there is a package file, the value will be the text content of the file.

        Returns:
            Dict[str, Optional[str]]: The mapping of repository names to package file contents.
        """
        LOG.info('Getting package files')

        op, org = self.organization_operation()

        # Get the name of all of the repositories
        repository = org.repositories.edges.node
        repository.name()

        # Get the object from the `master` branch
        package_file = repository.object(expression=f'master:{self.package_file_name}')

        # Get the text content of the package file
        package_file.__as__(schema.Blob).text()

        data = self.client.get_all(op, page_on='organization.repositories')

        return {r.node.name: getattr(r.node.object, 'text', None) for r in data.organization.repositories.edges}

    @cache_region.cache_on_arguments()
    def package_names(self) -> Dict[str, str]:  # noqa: WPS231, complexity
        """Returns the list of available packages from the GitHub Organization.

        Packages are determined by examining each repository and attempting to retrieve
        the package name from the contents of the package file within the repository.

        If a repository does not contain a matching file, or the package name cannot
        be inferred from the file, the repository is ignored.

        The set of repositories to consider can be filtered using `repo_pattern` which will be
        interpreted as a regular expression on the repository name. The value can be omitted if no
        filtering should occur.

        You can also explicitly control repository lists using `repo_include_list` and `repo_exclude_list`.

        Returns:
            Dict[str, str]: A dict of package names and their associated repositories.
        """
        LOG.info('Getting package names')

        packages = {}

        for repository_name, package_file_content in self.package_files().items():
            if not package_file_content:
                continue

            if self.repo_include_list and repository_name not in self.repo_include_list:
                continue

            if self.repo_exclude_list and repository_name in self.repo_exclude_list:
                continue

            if self.repo_pattern and not re.match(self.repo_pattern, repository_name):
                continue

            package_name = self.get_package_name(package_file_content)

            if package_name:
                packages[package_name] = repository_name

        return packages

    @classmethod
    def configure(cls, settings) -> Dict[str, Any]:
        base_config = super().configure(settings)
        organization = settings.get('auth.otc.github.organization')

        LOG.info(f'Configuring Github Auth with organization: {organization}')

        # Configure the cache region
        cache.configure_cache_region(cache_region, settings, prefix='auth.otc.github.cache')

        return {
            **base_config,
            'default_read': aslist(settings.get('pypi.default_read', [])),
            'default_write': aslist(settings.get('pypi.default_write', [])),
            'token': settings.get('auth.otc.github.token'),
            'organization': organization,
            'repo_pattern': settings.get('auth.otc.github.repo_pattern', '.*'),
            'repo_include_list': aslist(settings.get('auth.otc.github.repo_include_list', [])),
            'repo_exclude_list': aslist(settings.get('auth.otc.github.repo_exclude_list', [])),
        }

    @cache_region.cache_on_arguments()
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
        LOG.info('Checking user token')

        user_client = Client(token)

        op = user_client.operation()

        # Get the user node, and its login
        user = op.viewer()
        user.login()

        result = user_client.execute(op)

        # Ensure the username matches the token
        return hasattr(result, 'viewer') and getattr(result.viewer, 'login', None) == username  # noqa: WPS421, has/getattr

    @cache_region.cache_on_arguments()
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

        return username in self.users()

    @cache_region.cache_on_arguments()
    def teams(self) -> TeamMemberMap:
        """Returns a map of GitHub Team names and members.

        Each team has a list of tuples corresponding to members and their roles.

        Returns:
            TeamMemberMap: The teams and their members.
        """
        LOG.info('Getting teams')

        op, org = self.organization_operation()

        team = org.teams.edges.node
        team.name()

        membership = team.members.edges
        membership.role()

        member = membership.node
        member.login()

        data = self.client.get_all(op, page_on='organization.teams')
        teams = {}

        for t in data.organization.teams.edges:
            members = []
            teams[t.node.name] = members

            for m in t.node.members.edges:
                members.append((m.node.login, m.role))

        return teams

    @cache_region.cache_on_arguments()
    def groups(self, username: Optional[str] = None) -> List[str]:
        """Get a list of all groups.

        If a username is specified, get all groups to which the user belongs.

        Args:
            username (str, optional): The username.

        Returns:
            List[str]: The list of group names.
        """
        if username:
            user_data = self.user_data(username)
            return user_data['groups']

        return list(self.teams().keys())

    @cache_region.cache_on_arguments()
    def group_members(self, group: str) -> List[str]:
        """Get a list of users that belong to a group.

        Args:
            group (str): The name of the group.

        Returns:
            List[str]: The list usernames of the members of the group.
        """
        return [username for username, role in self.teams().get(group, [])]

    @cache_region.cache_on_arguments()
    def is_admin(self, username: str) -> bool:
        """Check if the user is an admin.

        Args:
            username (str): The username to check.

        Returns:
            bool: True if the user is an admin.
        """
        return self.users().get(username, False)

    def group_permissions(self, package: str) -> Dict[str, List[str]]:
        """Get a mapping of all groups to their permissions on a package.

        Args:
            package (str): The name of a python package

        Returns:
            dict: Mapping of group name to a list of permissions (which can contain 'read' and/or 'write')
        """
        return self.package_permissions(package, _teams_key)

    def user_permissions(self, package: str) -> Dict[str, List[str]]:
        """Get a mapping of all users to their permissions for a package.

        Args:
            package (str): The name of a python package.

        Returns:
            Dict[str, List[str]]: Mapping of username to a list of permissions (which can contain 'read' and/or 'write')
        """
        return self.package_permissions(package, _users_key)

    @cache_region.cache_on_arguments()
    def package_permissions(self, package: str, principal_type: str) -> Dict[str, List[str]]:
        """Get a mapping of all entities of the principal type to their permissions for a package.

        Args:
            package (str): The name of a python package.
            principal_type (str): The entity type ('users' or 'teams')

        Returns:
            Dict[str, List[str]]: Mapping of username to a list of permissions (which can contain 'read' and/or 'write')
        """
        assert principal_type in {_users_key, _teams_key}  # noqa: S101, use of assert

        repo = self.package_names().get(package, None)

        if not repo:
            return {}

        repo_perms = self.repository_permissions()[repo]

        return {u: list(p) for u, p in repo_perms[principal_type].items()}

    @cache_region.cache_on_arguments()
    def entity_package_permissions(self, entity_type: str, entity_name: str) -> List[Dict[str, Union[List[str], str]]]:
        """Get a list of all packages that a user has permissions on.

        Args:
            entity_type (str): The name of the entity.
            entity_name (str): The entity type ('users', or 'teams')

        Returns:
            List[Dict[str, Union[List[str], str]]]: List of dicts. Each dict contains 'package' (str) and 'permissions'.
        """
        LOG.info('Getting package permissions')

        assert entity_type in {_users_key, _teams_key}  # noqa: S101, use of assert

        all_repo_perms = self.repository_permissions()
        permissions = []

        # For each possible package, we want to retrieve the permissions
        # associated with the package's repo
        for package, repo in self.package_names().items():

            repo_perms = all_repo_perms[repo]

            # If the group has no associated permissions, skip
            if entity_name not in repo_perms[entity_type]:
                continue

            # Append the permissions
            package_perms = dict(package=package, permissions=list(repo_perms[entity_type][entity_name]))
            permissions.append(package_perms)

        return permissions

    def user_package_permissions(self, username: str) -> List[Dict[str, Union[List[str], str]]]:
        """Get a list of all packages that a user has permissions on.

        Args:
            username (str): The user.

        Returns:
            (List[Dict[str, Union[List[str], str]]]): List of dicts.
                Each dict contains 'package' (str) and 'permissions' (List[str]).
        """
        return self.entity_package_permissions(_users_key, username)

    def group_package_permissions(self, group: str) -> List[Dict[str, Union[List[str], str]]]:
        """Get a list of all packages that a group has permissions on.

        Args:
            group (str): The name of the group.

        Returns:
            List[Dict[str, Union[List[str], str]]]: List of dicts.
                Each dict contains 'package' (str) and 'permissions' (List[str]).
        """
        return self.entity_package_permissions(_teams_key, group)

    @cache_region.cache_on_arguments()
    def repository_permissions(self) -> Dict[str, RepositoryPermissions]:  # noqa: WPS231, cognitive complexity
        """Retrieve the permission set for all the repositories.

        Examples:
            ```
            repos = access.repository_permissions()
            ```

            Gives

            ```
            {
                "repo_1": {
                    "users": {
                        "user_1": {"read"},
                        "user_2": {"read", "write"}
                    },
                    "teams": {
                        "team_1": {"read"}
                    }
                },
                "repo_2": {
                    ...
                }
            }
            ```

        Returns:
            Dict[str, RepositoryPermissions]: A dict of repositories and their permissions.
        """
        LOG.info('Getting repository permissions')

        repositories = {}

        op, org = self.organization_operation()

        repository = org.repositories.edges.node
        repository.name()

        collaboration = repository.collaborators.edges

        # We want the list of users
        user = collaboration.node
        user.login()

        # We want to get all of the sources of permissions for the user on the
        # repo. The user can have permissions directly from the repo, or via a
        # team on the repo, or via the organization that contains the repo
        permission_source = collaboration.permission_sources
        permission_source.permission()

        permission_source.source.__as__(schema.Team).name()
        permission_source.source.__as__(schema.Repository).name()
        permission_source.source.__as__(schema.Organization).login()

        data = self.client.get_all(op, page_on='organization.repositories')

        org_type = 'Organization'
        repo_type = 'Repository'
        team_type = 'Team'

        for repo in data.organization.repositories.edges:
            permissions = dict(users={}, teams={})
            repositories[repo.node.name] = permissions

            for collab in repo.node.collaborators.edges:
                username = collab.node.login

                # We say that the direct permissions are those from the repo itself
                # and those from the Organization
                repo_and_org_permissions = {
                    p
                    for ps in collab.permission_sources
                    # Map the Github permission onto a pypicloud permission
                    for p in self.convert_permission(ps.permission)
                    if ps.source.__typename__ in {org_type, repo_type}
                }

                permissions[_users_key][username] = repo_and_org_permissions

                # Permissions can come from the Org, the Repo, or a Team
                # Here we deal with Team permissions
                for ps in collab.permission_sources:
                    if ps.source.__typename__ != team_type:
                        continue  # noqa: WPS220, nesting depth

                    if ps.source.name not in permissions[_teams_key]:
                        permissions[_teams_key][ps.source.name] = set()  # noqa: WPS220, nesting depth

                    permissions[_teams_key][ps.source.name].update(self.convert_permission(ps.permission))

        return repositories

    @cache_region.cache_on_arguments()
    def user_data(self, username: Optional[str] = None) -> Union[UserWithGroups, List[User]]:
        """Get a list of all users or data for a single user.

        Each user is a dict with a 'username' str, and 'admin' bool.
        If a username is passed in, instead return one user with the fields
        above plus a 'groups' list.

        Args:
            username (str, optional): The user for which to get the data.

        Returns:
            Union[UserWithGroups, List[User]]: The user with groups, or the list of users.
        """
        if username:
            return dict(username=username, admin=self.is_admin(username), groups=self.user_groups(username))

        return [dict(username=k, admin=v) for k, v in self.users().items()]

    @cache_region.cache_on_arguments()
    def user_groups(self, username: str) -> List[str]:
        """Return the list of groups for a user.

        Args:
            username (str): The username.

        Returns:
            List[str]: The list groups for the user.
        """
        return [team for team, user_roles in self.teams().items() if username in dict(user_roles)]

    @cache_region.cache_on_arguments()
    def users(self) -> Dict[str, bool]:
        """Return the list of users and their admin status.

        Returns:
            Dict[str, bool]: The set of users and their admin status.
        """
        LOG.info('Getting users')

        op, org = self.organization_operation()

        membership = org.members_with_role.edges
        membership.role()

        membership.node.login()

        data = self.client.get_all(op, page_on='organization.members_with_role')

        return {m.node.login: (m.role.lower() == GithubRoles.admin.value) for m in data.organization.members_with_role.edges}

    def check_health(self) -> Tuple[bool, str]:
        """Check the health of the access backend.

        This ensures that the provided access token can access the specified organization, and has
        the correct permissions.

        Returns:
            Tuple[bool, str]: Tuple that describes the health status and provides an optional status message.
        """
        try:
            # Run a query to check everything is running smoothly
            self.users()
            return (True, '')
        except Exception as ex:
            return (False, str(ex))

    def _get_password_hash(self, username: str) -> str:  # pragma: no cover
        return ''
