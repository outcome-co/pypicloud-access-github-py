"""Execute the GraphQL queries."""

from collections import defaultdict
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Type, TypeVar, cast

from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport
from outcome.pypicloud_access_github.graphql.queries import queries
from outcome.pypicloud_access_github.graphql.schemas.models.object import BlobObject
from outcome.pypicloud_access_github.graphql.schemas.models.organization import OrganizationMemberRole
from outcome.pypicloud_access_github.graphql.schemas.models.page_info import PageInfo
from outcome.pypicloud_access_github.graphql.schemas.models.repository import (
    DefaultRepositoryPermissionField,
    Repository,
    TeamPermissionGranter,
)
from outcome.pypicloud_access_github.graphql.schemas.models.team import TeamMemberRole
from outcome.pypicloud_access_github.graphql.schemas.models.user import User
from outcome.pypicloud_access_github.graphql.schemas.queries.get_current_user import GetCurrentUser
from outcome.pypicloud_access_github.graphql.schemas.queries.get_organization_members import GetOrganizationMembers
from outcome.pypicloud_access_github.graphql.schemas.queries.get_organization_package_files import GetOrganizationPackageFiles
from outcome.pypicloud_access_github.graphql.schemas.queries.get_organization_repository_permissions import (
    GetOrganizationRepositoryPermissions,
)
from outcome.pypicloud_access_github.graphql.schemas.queries.get_organization_teams import GetOrganizationTeams
from pydantic import BaseModel

_github_graphql_endpoint = 'https://api.github.com/graphql'
_default_page_size = 25

M = TypeVar('M', bound=BaseModel)
E = TypeVar('E')
P = TypeVar('P')

PageInfoExtractor = Callable[[M], PageInfo]

TupleSequence = Sequence[Tuple[E, P]]


class Github:  # noqa: WPS214 # pragma: only-covered-in-integration-tests
    _client: Client

    def __init__(self, token: str) -> None:
        headers = {'Authorization': f'Bearer {token}'}
        transport = RequestsHTTPTransport(_github_graphql_endpoint, headers=headers)
        self._client = Client(transport=transport, fetch_schema_from_transport=False)

    def get_current_user(self) -> User:
        query = queries.get_current_user
        result = self._get(query, GetCurrentUser)
        return result.viewer

    def get_organization_members(self, organization: str) -> TupleSequence[User, OrganizationMemberRole]:
        query = queries.get_organization_members
        members: TupleSequence[User, OrganizationMemberRole] = []

        params = {'login': organization}

        def page_extractor(page: GetOrganizationMembers) -> PageInfo:
            assert page.organization.members_with_role is not None and page.organization.members_with_role.page_info is not None
            return page.organization.members_with_role.page_info

        for page in self._get_all(query, GetOrganizationMembers, params, page_extractor):
            assert page.organization.members_with_role is not None
            assert page.organization.members_with_role.edges is not None
            for edge in page.organization.members_with_role.edges:
                members.append((edge.node, edge.role))

        return members

    def get_organization_package_files(self, organization: str, package_file: str) -> TupleSequence[Repository, Optional[str]]:
        query = queries.get_organization_package_files
        package_files: TupleSequence[Repository, Optional[str]] = []

        params = {'login': organization, 'expression': f'master:{package_file}'}

        def page_extractor(page: GetOrganizationPackageFiles) -> PageInfo:
            assert page.organization.repositories is not None and page.organization.repositories.page_info is not None
            return page.organization.repositories.page_info

        for page in self._get_all(query, GetOrganizationPackageFiles, params, page_extractor):
            assert page.organization.repositories is not None and page.organization.repositories.edges is not None
            for edge in page.organization.repositories.edges:
                repo = edge.node
                gitobject = repo.gitobject

                if isinstance(gitobject, BlobObject):
                    package_files.append((repo, gitobject.text))
                else:
                    package_files.append((repo, None))

        return package_files

    def get_organization_teams(self, organization: str) -> Dict[str, TupleSequence[User, TeamMemberRole]]:
        query = queries.get_organization_teams
        teams: Dict[str, TupleSequence[User, TeamMemberRole]] = {}

        params = {'login': organization}

        def page_info_extractor(page: GetOrganizationTeams) -> PageInfo:
            assert page.organization.teams is not None and page.organization.teams.page_info is not None
            return page.organization.teams.page_info

        for page in self._get_all(query, GetOrganizationTeams, params, page_info_extractor):
            assert page.organization.teams is not None and page.organization.teams.edges is not None
            for edge in page.organization.teams.edges:
                team = edge.node
                members: List[Tuple[User, TeamMemberRole]] = []
                teams[team.name] = members

                assert team.members.edges is not None

                for member in team.members.edges:
                    members.append((member.node, member.role))

        return teams

    def get_organization_repository_permissions(  # noqa: WPS320, WPS218, WPS231
        self, organization: str,
    ) -> Sequence[
        Tuple[
            str,
            TupleSequence[User, Sequence[DefaultRepositoryPermissionField]],
            TupleSequence[str, Sequence[DefaultRepositoryPermissionField]],
        ]
    ]:
        query = queries.get_organization_repository_permissions
        repository_permissions: Sequence[
            Tuple[
                str,
                TupleSequence[User, Sequence[DefaultRepositoryPermissionField]],
                TupleSequence[str, Sequence[DefaultRepositoryPermissionField]],
            ]
        ] = []

        params = {'login': organization}

        def page_info_extractor(page: GetOrganizationRepositoryPermissions) -> PageInfo:
            assert page.organization.repositories is not None and page.organization.repositories.page_info is not None
            return page.organization.repositories.page_info

        for page in self._get_all(query, GetOrganizationRepositoryPermissions, params, page_info_extractor):
            assert page.organization.repositories is not None and page.organization.repositories.edges is not None
            for edge in page.organization.repositories.edges:
                repo = edge.node

                repo_user_permissions: TupleSequence[User, Sequence[DefaultRepositoryPermissionField]] = []
                repo_team_permissions: TupleSequence[str, Sequence[DefaultRepositoryPermissionField]] = []

                team_permission_accumulator: Dict[str, List[DefaultRepositoryPermissionField]] = defaultdict(list)

                repo_permissions = (repo.name, repo_user_permissions, repo_team_permissions)
                repository_permissions.append(repo_permissions)

                assert repo.collaborators is not None and repo.collaborators.edges is not None

                for collaborator in repo.collaborators.edges:
                    u_permissions: Sequence[DefaultRepositoryPermissionField] = []

                    repo_user_permissions.append((collaborator.node, u_permissions))

                    for permission in collaborator.permission_sources:
                        if permission.source.typename == 'Team':  # noqa: WPS220
                            # NOTE: this assert shouldn't be necessary
                            assert isinstance(permission.source, TeamPermissionGranter)
                            team_permission_accumulator[permission.source.name].append(permission.permission)  # noqa: WPS220
                        else:
                            u_permissions.append(permission.permission)  # noqa: WPS220

                for team, t_permissions in team_permission_accumulator.items():
                    repo_team_permissions.append((team, t_permissions))

        return repository_permissions

    def _get_all(
        self, query_str: str, schema: Type[M], parameters: Mapping[str, object], page_info_extractor: PageInfoExtractor[M],
    ) -> Sequence[M]:
        pages: List[M] = []

        has_next_page = True
        next_request_parameters = {'first': _default_page_size, **parameters}

        while has_next_page:
            result = self._get(query_str, schema, next_request_parameters)
            pages.append(result)

            page_info = page_info_extractor(result)

            has_next_page = page_info.has_next_page
            next_request_parameters = {**next_request_parameters, 'after': page_info.end_cursor}

        return pages

    def _get(self, query_str: str, schema: Type[M], parameters: Optional[Mapping[str, object]] = None) -> M:
        query = gql(query_str)
        result = cast(Dict[str, object], self._client.execute(query, variable_values=(parameters or {})))
        return schema(**result)
