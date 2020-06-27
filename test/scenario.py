from enum import Enum
from typing import Any, Dict, List

from pydantic import BaseModel, validator


class BaseSchema(BaseModel):
    class Config:
        extra = 'forbid'


class RepositoryRole(Enum):
    admin = 'admin'
    maintain = 'maintain'
    read = 'read'
    triage = 'triage'
    write = 'write'


class RepositoryMembership(BaseSchema):
    name: str
    role: RepositoryRole


class Repository(BaseSchema):
    name: str
    private: bool = False
    files: Dict[str, str] = {}
    meta: Dict[str, Any] = {}

    collaborators: List[RepositoryMembership] = []

    def update_users(self, user_map: Dict[str, str]):
        for user in self.collaborators:
            user.name = user_map.get(user.name, user.name)


class Team(BaseSchema):
    name: str
    members: List[str] = []

    repositories: List[RepositoryMembership] = []

    def update_users(self, user_map: Dict[str, str]):
        self.members = [user_map.get(m, m) for m in self.members]  # noqa: WPS601


Team.update_forward_refs()


class OrganizationRole(Enum):
    member = 'member'
    admin = 'admin'


class UserMembership(BaseSchema):
    name: str


class Scenario(BaseSchema):
    # Users has to go before teams for validation
    # https://pydantic-docs.helpmanual.io/usage/models/#field-ordering
    users: List[UserMembership] = []
    repositories: List[Repository] = []
    teams: List[Team] = []

    def update_users(self, user_map: Dict[str, str]):
        for user in self.users:
            user.name = user_map.get(user.name, user.name)

        for team in self.teams:
            team.update_users(user_map)

        for repo in self.repositories:
            repo.update_users(user_map)

    @validator('teams')
    def check_team_memberships(cls, teams: List[Team], values):  # noqa: N805
        all_users = {u.name for u in values.get('users', [])}

        for team in teams:
            team_users = set(team.members)
            if not team_users.issubset(all_users):
                raise ValueError(f'Unknown users: {team_users - all_users}')

        return teams

    @validator('repositories')
    def check_repository_collaborators(cls, repositories: List[Repository], values):  # noqa: N805
        all_users = {u.name for u in values.get('users', [])}

        for repo in repositories:
            repo_users = {m.name for m in repo.collaborators}
            if not repo_users.issubset(all_users):
                raise ValueError(f'Unknown users: {repo_users - all_users}')

        return repositories

    @validator('teams')
    def check_team_repositories(cls, teams: List[Team], values):  # noqa: N805
        all_repos = {r.name for r in values.get('repositories', [])}

        for team in teams:
            team_repos = {r.name for r in team.repositories}
            if not team_repos.issubset(all_repos):
                raise ValueError(f'Unknown repos: {team_repos - all_repos}')

        return teams
