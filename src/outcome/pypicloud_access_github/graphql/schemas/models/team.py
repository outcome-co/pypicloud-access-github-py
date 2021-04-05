"""Type definition."""

from __future__ import annotations

from enum import Enum

from outcome.pypicloud_access_github.graphql.schemas.models.connection import Connection
from outcome.pypicloud_access_github.graphql.schemas.models.edge import Edge
from outcome.pypicloud_access_github.graphql.schemas.models.user import User
from pydantic import BaseModel


class Team(BaseModel):
    name: str
    members: TeamMemberConnection


class TeamEdge(Edge[Team]):
    ...


class TeamMemberRole(Enum):
    maintainer = 'MAINTAINER'
    member = 'MEMBER'


class TeamMemberEdge(Edge[User]):
    role: TeamMemberRole


class TeamMemberConnection(Connection[TeamMemberEdge, User]):
    ...


class TeamConnection(Connection[TeamEdge, Team]):
    ...


Team.update_forward_refs()
