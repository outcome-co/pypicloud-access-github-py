import json
from contextlib import contextmanager
from typing import Dict, List

import tenacity
from github import Github, GithubException, Organization

from .scenario import Repository, Scenario, Team  # noqa: WPS300

_role_map = {
    'write': 'push',
    'read': 'pull',
}


def map_role(role):
    return _role_map.get(role, role)


def load_scenario(path: str, user_map: Dict[str, str], session_id: str) -> Scenario:
    with open(path, 'r') as handle:
        data = json.load(handle)

    scenario = Scenario(**data)

    scenario.set_session_id(session_id)
    scenario.update_users(user_map)

    return scenario


@contextmanager
def github_scenario(token: str, organization: str, path: str, user_map: Dict[str, str], session_id: str):
    scenario = load_scenario(path, user_map, session_id)
    client = Github(token)
    organization = client.get_organization(organization)

    reset_github(organization, scenario)

    try:
        build_scenario(client, organization, scenario)
        yield scenario
    finally:
        reset_github(organization, scenario)


def reset_github(organization: Organization.Organization, scenario: Scenario) -> None:

    scenario_team_names = {t.name for t in scenario.teams}
    scenario_repo_names = {r.name for r in scenario.repositories}

    # Delete teams
    for team in organization.get_teams():
        try:
            if team.name in scenario_team_names:
                team.delete()

        # Teams are hierarchical, so we may have already deleted it
        # by deleting a parent
        except Exception:  # noqa: S110
            pass

    # Delete repos
    for repo in organization.get_repos():
        try:
            if repo.name in scenario_repo_names:
                repo.delete()
        except GithubException:
            pass


class UserCache(dict):  # noqa: WPS600
    def __init__(self, client: Github):
        self.client = client

    def __missing__(self, username: str):
        self[username] = self.client.get_user(username)
        return self[username]


def build_scenario(client: Github, organization: Organization.Organization, scenario: Scenario) -> None:
    user_cache = UserCache(client)

    build_repositories(user_cache, organization, scenario.repositories)
    build_teams(client, user_cache, organization, scenario.teams)


def build_repositories(user_cache: UserCache, organization: Organization.Organization, repositories: List[Repository]):
    for repo in repositories:
        new_repo = organization.create_repo(name=repo.name, private=repo.private)

        # Sometimes the repo isn't ready when we try to add users or files, so we
        # try a couple of times
        @tenacity.retry(stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
        def add_user_to_repo(user, role):
            new_repo.add_to_collaborators(user, role)

        @tenacity.retry(stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
        def add_file_to_repo(file, file_content):
            new_repo.create_file(file, 'Test File', file_content)

        for user in repo.collaborators:
            add_user_to_repo(user_cache[user.name], map_role(user.role.value))

        for file, file_content in repo.files.items():
            add_file_to_repo(file, file_content)


def build_teams(
    client: Github, user_cache: UserCache, organization: Organization.Organization, teams: List[Team],
):
    creator = client.get_user()
    creator_user = user_cache[creator.login]

    for team in teams:
        new_team = organization.create_team(name=team.name, privacy='closed')

        # We want to remove the creator, since they may not
        # be part of the scenario
        new_team.remove_from_members(creator_user)

        for member in team.members:
            user = user_cache[member]
            new_team.add_membership(user, 'member')

        @tenacity.retry(stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
        def add_team_to_repo(repo_name, role):
            repository = organization.get_repo(repo_name)
            new_team.add_to_repos(repository)
            new_team.set_repo_permission(repository, role)

        for repo in team.repositories:
            add_team_to_repo(repo.name, map_role(repo.role.value))
