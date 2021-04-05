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
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypedDict,
    TypeVar,
    Union,
    cast,
    overload,
)

from dogpile.cache import CacheRegion
from github import Github as GithubRESTClient
from outcome.pypicloud_access_github.graphql.github import Github
from outcome.pypicloud_access_github.graphql.schemas.models.organization import OrganizationMemberRole
from outcome.pypicloud_access_github.graphql.schemas.models.repository import DefaultRepositoryPermissionField
from outcome.pypicloud_access_github.graphql.schemas.models.team import TeamMemberRole
from outcome.utils import cache
from passlib.apps import LazyCryptContext
from pypicloud.access.base import ONE_WEEK, IAccessBackend
from pyramid.settings import aslist

LOG = logging.getLogger(__name__)

# Build a new dogpile.cache cache region
# we'll configure it later when the Access.configure method is called
cache_region: CacheRegion = cache.get_cache_region()


_read_permission = 'read'
_write_permission = 'write'


PypiPermission = Union[Literal['read'], Literal['write']]


# Mapping from Github roles to pypi permissions
_permissions_map: Dict[DefaultRepositoryPermissionField, Set[PypiPermission]] = {
    DefaultRepositoryPermissionField.admin: {_read_permission, _write_permission},
    DefaultRepositoryPermissionField.write: {_read_permission, _write_permission},
    DefaultRepositoryPermissionField.read: {_read_permission},
    DefaultRepositoryPermissionField.none: set(),
}

_teams_key = 'teams'
_users_key = 'users'

Entity = Literal['users', 'teams']

UserRole = Tuple[str, TeamMemberRole]
TeamMemberMap = Dict[str, Sequence[UserRole]]

C = TypeVar('C', bound=Callable[..., Any])


# A workaround the incorrect typing on the cache_on_arguments method
def cacheable(fn: C) -> C:
    return cast(C, cache_region.cache_on_arguments()(fn))


class User(TypedDict):
    username: str
    admin: bool
    groups: Optional[Sequence[str]]


class RepositoryPermissions(TypedDict):
    users: Dict[str, Set[PypiPermission]]
    teams: Dict[str, Set[PypiPermission]]


class PackagePermissions(TypedDict):
    package: str
    permissions: Sequence[PypiPermission]


class Access(abc.ABC, IAccessBackend):  # pragma: only-covered-in-integration-tests; # noqa: WPS214

    client: Github
    token: str
    organization_name: str
    repo_exclude_list: Optional[List[str]]
    repo_include_list: Optional[List[str]]

    def __init__(  # noqa: WPS211, too many arguments
        self,
        request: Optional[object] = None,
        default_read: Optional[Sequence[str]] = None,
        default_write: Optional[Sequence[str]] = None,
        disallow_fallback: Optional[Iterable[str]] = (),
        cache_update: Optional[Sequence[str]] = None,
        pwd_context: Optional[LazyCryptContext] = None,
        token_expiration: int = ONE_WEEK,
        signing_key: Optional[str] = None,
        token: Optional[str] = None,
        organization: Optional[str] = None,
        repo_pattern: Optional[str] = None,
        repo_include_list: Optional[List[str]] = None,
        repo_exclude_list: Optional[List[str]] = None,
    ) -> None:

        super().__init__(
            request, default_read, default_write, disallow_fallback, cache_update, pwd_context, token_expiration, signing_key,
        )

        assert organization
        assert token

        self.organization_name = organization
        self.client = Github(token)
        self.token = token

        self.repo_pattern = repo_pattern
        self.repo_include_list = repo_include_list
        self.repo_exclude_list = repo_exclude_list

    @cacheable
    def default_organization_permissions(self) -> Set[PypiPermission]:
        # We have to retrieve the default organization permission to determine the read/write
        # permissions for users with no explicit permissions. This value is only accessible via
        # the REST API

        rest_client = GithubRESTClient(self.token)
        default_permission_as_string = rest_client.get_organization(self.organization_name).default_repository_permission

        # We need to convert it to an instance of the enum to use the mapping function
        default_permission = DefaultRepositoryPermissionField[default_permission_as_string]

        return self.convert_permission(default_permission)

    @abc.abstractmethod
    def get_package_name(self, package_file_content: str) -> Optional[str]:  # pragma: no cover
        ...

    @property
    @abc.abstractmethod
    def package_file_name(self) -> str:  # pragma: no cover
        ...

    @staticmethod
    def convert_permission(github_role: DefaultRepositoryPermissionField) -> Set[PypiPermission]:
        """Convert a Github role to read/write permissions.

        Args:
            github_role (DefaultRepositoryPermissionField): The Github role.

        Returns:
            Set[str]: The set of permissions (either 'read' or 'write', or both)
        """
        return _permissions_map[github_role]

    @cacheable
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

        package_files = self.client.get_organization_package_files(self.organization_name, self.package_file_name)

        return {repo.name: content for repo, content in package_files}

    @cacheable
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

        packages: Dict[str, str] = {}

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
    def configure(cls, settings: Dict[str, object]) -> Dict[str, object]:
        base_config = super().configure(settings)
        organization = settings.get('auth.otc.github.organization')

        assert isinstance(organization, str)

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

    @cacheable
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

        try:
            user_client = Github(token)
            current_user = user_client.get_current_user()

            # Ensure the username matches the token
            return current_user.login == username
        except Exception:
            LOG.exception('User verification failed')
            return False

    @cacheable
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

    @cacheable
    def teams(self) -> TeamMemberMap:
        """Returns a map of GitHub Team names and members.

        Each team has a list of tuples corresponding to members and their roles.

        Returns:
            TeamMemberMap: The teams and their members.
        """
        LOG.info('Getting teams')

        teams = self.client.get_organization_teams(self.organization_name)

        return {name: [(user.login, role) for user, role in members] for name, members in teams.items()}

    @cacheable
    def groups(self, username: Optional[str] = None) -> Sequence[str]:  # type: ignore
        """Get a list of all groups.

        If a username is specified, get all groups to which the user belongs.

        Args:
            username (str, optional): The username.

        Returns:
            List[str]: The list of group names.
        """
        if username:
            user_data = self.user_data(username)
            return user_data['groups'] or []

        return list(self.teams().keys())

    @cacheable
    def group_members(self, group: str) -> List[str]:
        """Get a list of users that belong to a group.

        Args:
            group (str): The name of the group.

        Returns:
            List[str]: The list usernames of the members of the group.
        """
        return [username for username, _ in self.teams().get(group, [])]

    @cacheable
    def is_admin(self, username: str) -> bool:
        """Check if the user is an admin.

        Args:
            username (str): The username to check.

        Returns:
            bool: True if the user is an admin.
        """
        return self.users().get(username, False)

    def group_permissions(self, package: str) -> Dict[str, List[PypiPermission]]:
        """Get a mapping of all groups to their permissions on a package.

        Args:
            package (str): The name of a python package

        Returns:
            dict: Mapping of group name to a list of permissions (which can contain 'read' and/or 'write')
        """
        permissions = self.package_permissions(package, _teams_key)

        LOG.debug(f'Checking group permissions for package: {package}: {permissions}')

        return permissions

    def user_permissions(self, package: str) -> Dict[str, List[PypiPermission]]:
        """Get a mapping of all users to their permissions for a package.

        Args:
            package (str): The name of a python package.

        Returns:
            Dict[str, List[str]]: Mapping of username to a list of permissions (which can contain 'read' and/or 'write')
        """
        permissions = self.package_permissions(package, _users_key)

        LOG.debug(f'Checking user permissions for package: {package}: {permissions}')

        return permissions

    @cacheable
    def package_permissions(self, package: str, principal_type: Entity) -> Dict[str, List[PypiPermission]]:
        """Get a mapping of all entities of the principal type to their permissions for a package.

        Args:
            package (str): The name of a python package.
            principal_type (Entity): The entity type ('users' or 'teams')

        Returns:
            Dict[str, List[PypiPermission]]: Mapping of username to a list of permissions
        """
        assert principal_type in {_users_key, _teams_key}  # noqa: S101, use of assert

        repo = self.package_names().get(package, None)

        if not repo:
            return {}

        repo_perms = self.repository_permissions()[repo]

        return {u: list(p) for u, p in repo_perms[principal_type].items()}

    @cacheable
    def entity_package_permissions(self, entity_type: Entity, entity_name: str) -> Sequence[PackagePermissions]:
        """Get a list of all packages that a user has permissions on.

        Args:
            entity_type (Entity): The name of the entity.
            entity_name (str): The entity type ('users', or 'teams')

        Returns:
            List[PackagePermissions]: List of dicts. Each dict contains 'package' (str) and 'permissions'.
        """
        LOG.info('Getting package permissions')

        assert entity_type in {_users_key, _teams_key}  # noqa: S101, use of assert

        all_repo_perms = self.repository_permissions()
        permissions: List[PackagePermissions] = []

        # For each possible package, we want to retrieve the permissions
        # associated with the package's repo
        for package, repo in self.package_names().items():

            repo_perms = all_repo_perms[repo]

            # If the group has no associated permissions, skip
            if entity_name not in repo_perms[entity_type]:
                continue

            # NOTE: sets of literals seem to be cast as sequences of str, so we need to recast
            entity_permissions = cast(Sequence[PypiPermission], list(repo_perms[entity_type][entity_name]))

            # Append the permissions
            package_perms: PackagePermissions = {'package': package, 'permissions': entity_permissions}
            permissions.append(package_perms)

        return permissions

    def user_package_permissions(self, username: str) -> Sequence[PackagePermissions]:  # type: ignore
        """Get a list of all packages that a user has permissions on.

        Args:
            username (str): The user.

        Returns:
            (List[Dict[str, Union[List[str], str]]]): List of dicts.
                Each dict contains 'package' (str) and 'permissions' (List[str]).
        """
        permissions = self.entity_package_permissions(_users_key, username)

        LOG.debug(f'Package permissions for user: {username}: {permissions}')

        return permissions

    def group_package_permissions(self, group: str) -> Sequence[PackagePermissions]:  # type: ignore
        """Get a list of all packages that a group has permissions on.

        Args:
            group (str): The name of the group.

        Returns:
            List[Dict[str, Union[List[str], str]]]: List of dicts.
                Each dict contains 'package' (str) and 'permissions' (List[str]).
        """
        permissions = self.entity_package_permissions(_teams_key, group)

        LOG.debug(f'Package permissions for group: {group}: {permissions}')

        return permissions

    @cacheable
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

        repositories: Dict[str, RepositoryPermissions] = {}

        all_repo_permissions = self.client.get_organization_repository_permissions(self.organization_name)

        for repo, user_permissions, team_permissions in all_repo_permissions:
            repo_perms: RepositoryPermissions = {'users': {}, 'teams': {}}

            for user, u_permissions in user_permissions:
                user_perms: Set[PypiPermission] = self.default_organization_permissions()

                for u_p in u_permissions:
                    user_perms = user_perms.union(self.convert_permission(u_p))

                repo_perms['users'][user.login] = user_perms

            for team, t_permissions in team_permissions:
                team_perms: Set[PypiPermission] = cast(Set[PypiPermission], set())

                for t_p in t_permissions:
                    team_perms = team_perms.union(self.convert_permission(t_p))

                repo_perms['teams'][team] = team_perms

            repositories[repo] = repo_perms

        return repositories

    @overload
    def user_data(self) -> List[User]:  # pragma: no cover
        ...

    @overload
    def user_data(self, username: str) -> User:  # pragma: no cover
        ...

    @cacheable
    def user_data(self, username: Optional[str] = None) -> Union[User, List[User]]:
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
            return {'username': username, 'admin': self.is_admin(username), 'groups': self.user_groups(username)}

        return [{'username': k, 'admin': v, 'groups': None} for k, v in self.users().items()]

    @cacheable
    def user_groups(self, username: str) -> List[str]:
        """Return the list of groups for a user.

        Args:
            username (str): The username.

        Returns:
            List[str]: The list groups for the user.
        """
        return [team for team, user_roles in self.teams().items() if username in dict(user_roles)]

    @cacheable
    def users(self) -> Dict[str, bool]:
        """Return the list of users and their admin status.

        Returns:
            Dict[str, bool]: The set of users and their admin status.
        """
        LOG.info('Getting users')

        members = self.client.get_organization_members(self.organization_name)
        return {user.login: role == OrganizationMemberRole.admin for user, role in members}

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
            self.default_organization_permissions()
            return (True, '')
        except Exception as ex:
            return (False, str(ex))

    def _get_password_hash(self, username: str) -> str:  # pragma: no cover
        return ''
