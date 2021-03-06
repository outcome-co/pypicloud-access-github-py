from enum import Enum
from typing import Any, Dict, List, Optional, Set, TypedDict

import pystache
from pydantic import BaseModel, validator


class BaseSchema(BaseModel):
    class Config:
        extra = 'forbid'


class SessionObject(BaseSchema):
    session_id: Optional[str] = None

    def set_session_id(self, session_id: str):  # noqa: WPS615
        assert self.session_id is None
        self.session_id = session_id  # noqa: WPS601


class NamedSessionObject(SessionObject):
    name: str

    def set_session_id(self, session_id: str):
        super().set_session_id(session_id)
        self.name = f'{self.name}-{session_id}'


class RepositoryRole(Enum):
    admin = 'admin'
    maintain = 'maintain'
    read = 'read'
    triage = 'triage'
    write = 'write'


class RepositoryMembership(NamedSessionObject):
    role: RepositoryRole


class Repository(NamedSessionObject):
    private: bool = False
    files: Dict[str, str] = {}
    meta: Dict[str, Any] = {}

    collaborators: List[RepositoryMembership] = []

    def update_users(self, user_map: Dict[str, str]):
        for user in self.collaborators:
            user.name = user_map.get(user.name, user.name)

    def set_session_id(self, session_id: str):
        super().set_session_id(session_id)

        for file, file_content in self.files.items():
            self.files[file] = pystache.render(file_content, session_id=session_id)

        package = self.meta.get('package', None)
        if package:
            self.meta['package'] = f'{package}-{session_id}'


class Team(NamedSessionObject):
    members: List[str] = []
    repositories: List[RepositoryMembership] = []

    def update_users(self, user_map: Dict[str, str]):
        self.members = [user_map.get(m, m) for m in self.members]  # noqa: WPS601

    def set_session_id(self, session_id: str):
        super().set_session_id(session_id)
        for membership in self.repositories:
            membership.set_session_id(session_id)


Team.update_forward_refs()


class OrganizationRole(Enum):
    member = 'member'
    admin = 'admin'


class UserMembership(BaseSchema):
    name: str


class ScenarioValues(TypedDict):
    users: List[UserMembership]
    repositories: List[Repository]
    teams: List[Team]


class Scenario(SessionObject):
    name: str
    # Users has to go before teams for validation
    # https://pydantic-docs.helpmanual.io/usage/models/#field-ordering
    users: List[UserMembership] = []
    repositories: List[Repository] = []
    teams: List[Team] = []

    @property
    def team_names(self) -> Set[str]:
        return {t.name for t in self.teams}

    @property
    def repo_names(self) -> Set[str]:
        return {r.name for r in self.repositories}

    def set_session_id(self, session_id: str) -> None:
        super().set_session_id(session_id)

        assert self.session_id

        for team in self.teams:
            team.set_session_id(self.session_id)

        for repo in self.repositories:
            repo.set_session_id(self.session_id)

    def update_users(self, user_map: Dict[str, str]):
        for user in self.users:
            user.name = user_map.get(user.name, user.name)

        for team in self.teams:
            team.update_users(user_map)

        for repo in self.repositories:
            repo.update_users(user_map)

    @validator('teams')
    def check_team_memberships(cls, teams: List[Team], values: ScenarioValues):  # noqa: N805
        all_users = {u.name for u in values.get('users', [])}

        for team in teams:
            team_users = set(team.members)
            if not team_users.issubset(all_users):
                raise ValueError(f'Unknown users: {team_users - all_users}')  # noqa: WPS237

        return teams

    @validator('repositories')
    def check_repository_collaborators(cls, repositories: List[Repository], values: ScenarioValues):  # noqa: N805
        all_users = {u.name for u in values.get('users', [])}

        for repo in repositories:
            repo_users = {m.name for m in repo.collaborators}
            if not repo_users.issubset(all_users):
                raise ValueError(f'Unknown users: {repo_users - all_users}')  # noqa: WPS237

        return repositories

    @validator('teams')
    def check_team_repositories(cls, teams: List[Team], values: ScenarioValues):  # noqa: N805
        all_repos = {r.name for r in values.get('repositories', [])}

        for team in teams:
            team_repos = {r.name for r in team.repositories}
            if not team_repos.issubset(all_repos):
                raise ValueError(f'Unknown repos: {team_repos - all_repos}')  # noqa: WPS237

        return teams
