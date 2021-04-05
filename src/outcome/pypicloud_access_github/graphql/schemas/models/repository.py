"""Type definition."""

from enum import Enum
from typing import Literal, Optional, Sequence, Union

from outcome.pypicloud_access_github.graphql.schemas.models.connection import Connection
from outcome.pypicloud_access_github.graphql.schemas.models.edge import Edge
from outcome.pypicloud_access_github.graphql.schemas.models.object import GitObject
from outcome.pypicloud_access_github.graphql.schemas.models.user import User
from pydantic import BaseModel, Field


class DefaultRepositoryPermissionField(Enum):
    none = 'NONE'
    read = 'READ'
    write = 'WRITE'
    admin = 'ADMIN'


# In the schema, these are actually the real Organization, Team, etc. classes, but
# we simplify for our use case


class OrganizationPermissionGranter(BaseModel):
    typename: Literal['Organization'] = Field(..., alias='__typename')
    login: str


class TeamPermissionGranter(BaseModel):
    typename: Literal['Team'] = Field(..., alias='__typename')
    name: str


class RepositoryPermissionGranter(BaseModel):
    typename: Literal['Repository'] = Field(..., alias='__typename')
    name: str


PermissionGranter = Union[OrganizationPermissionGranter, TeamPermissionGranter, RepositoryPermissionGranter]


class PermissionSource(BaseModel):
    permission: DefaultRepositoryPermissionField
    source: PermissionGranter


class RepositoryCollaboratorEdge(Edge[User]):
    permission_sources: Sequence[PermissionSource] = Field(..., alias='permissionSources')


class RepositoryCollaboratorConnection(Connection[RepositoryCollaboratorEdge, User]):
    ...


class Repository(BaseModel):
    name: str
    gitobject: Optional[GitObject] = Field(None, alias='object')
    collaborators: Optional[RepositoryCollaboratorConnection]


class RepositoryEdge(Edge[Repository]):
    ...


class RepositoryConnection(Connection[RepositoryEdge, Repository]):
    ...
