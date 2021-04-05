"""Load the GraphQL queries."""

from dataclasses import dataclass
from pathlib import Path

query_directory = Path(Path(__file__).parent, 'queries')


def load_query(name: str) -> str:
    filename = f'{name}.graphql'
    absolute_path = Path(query_directory, filename)
    with open(absolute_path, 'r') as handle:
        return handle.read()


@dataclass
class Queries:
    get_current_user: str
    get_organization_members: str
    get_organization_package_files: str
    get_organization_teams: str
    get_organization_repository_permissions: str


queries = Queries(
    get_current_user=load_query('getCurrentUser'),
    get_organization_members=load_query('getOrganizationMembers'),
    get_organization_package_files=load_query('getOrganizationPackageFiles'),
    get_organization_teams=load_query('getOrganizationTeams'),
    get_organization_repository_permissions=load_query('getOrganizationRepositoryPermissions'),
)

__all__ = ('queries',)
