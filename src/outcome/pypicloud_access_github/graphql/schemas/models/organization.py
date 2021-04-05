"""Type definition."""

from enum import Enum
from typing import Optional

from outcome.pypicloud_access_github.graphql.schemas.models.connection import Connection
from outcome.pypicloud_access_github.graphql.schemas.models.edge import Edge
from outcome.pypicloud_access_github.graphql.schemas.models.repository import RepositoryConnection
from outcome.pypicloud_access_github.graphql.schemas.models.team import TeamConnection
from outcome.pypicloud_access_github.graphql.schemas.models.user import User
from pydantic import BaseModel, Field


class OrganizationMemberRole(Enum):
    member = 'MEMBER'
    admin = 'ADMIN'


class OrganizationMemberEdge(Edge[User]):
    role: OrganizationMemberRole


class OrganizationMemberConnection(Connection[OrganizationMemberEdge, User]):
    ...


class Organization(BaseModel):
    members_with_role: Optional[OrganizationMemberConnection] = Field(None, alias='membersWithRole')
    repositories: Optional[RepositoryConnection]
    teams: Optional[TeamConnection]
