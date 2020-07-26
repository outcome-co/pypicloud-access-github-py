from outcome.devkit.test_helpers import skip_for_unit
from outcome.pypicloud_access_github import Access

from ..scenario import Scenario


@skip_for_unit
class TestGetAll:
    def test_get_multiple_pages(self, github_access: Access, multiple_empty_repos_scenario: Scenario):
        op, org = github_access.organization_operation()

        # Retrieve one repo at a time
        org.repositories(first=1).edges.node.name()
        one_record = github_access.client.get(op)
        assert len(one_record.organization.repositories.edges) == 1

        # Retrieve all repos, one at a time (because of the 'first=1' above)
        all_records = github_access.client.get_all(op, page_on='organization.repositories')

        # Get the names of all the retrieved repos, as a set
        repo_names = {r.node.name for r in all_records.organization.repositories.edges}

        # Ensure that we retrieved at least the repos in the scenario
        assert multiple_empty_repos_scenario.team_names.issubset(repo_names)
