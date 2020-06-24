from outcome.devkit.test_helpers import skip_for_unit
from outcome.pypicloud_access_github import Access


@skip_for_unit
class TestGetAll:
    def test_get_multiple_pages(self, github_access: Access, multiple_empty_repos_scenario):
        op, org = github_access.organization_operation()

        org.repositories(first=1).edges.node.name()

        one_record = github_access.client.get(op)

        assert len(one_record.organization.repositories.edges) == 1

        all_records = github_access.client.get_all(op, page_on='organization.repositories')

        # The number of repos in the org
        number_of_repos = len(multiple_empty_repos_scenario.repositories)

        assert len(all_records.organization.repositories.edges) == number_of_repos
