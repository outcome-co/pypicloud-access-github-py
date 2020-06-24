# Integration Tests

This plugin's test suite relies mainly on integration tests, which interact directly with the Github API.

The integration test suite will automatically setup and tear down all of the Github resources it requires (teams, repos, etc.).

**Note** You should use a dedicated test Organization, as the test suite will **delete all of the contents of the organization** during tests.

## Setup

### Github

You will need to set up the following (all resources are free-plan resources):

- A Github Organization
- A Github user that is an admin of the Organization (referred to below as `admin-user`, but you can choose any username)
- A Github user that is a non-admin member of the Organization (referred to below as `member-user`, but you can choose any username)
- A Github user that is not a member of the Organization (referred to below as `non-member-user`, but you can choose any username)
- Personal access tokens for each user, with the `repo` scope
- A Personal access token that has full admin access to the Organization (can be `member-user`)

### Environment Variables

The test suite will require the following environment variables. You can place them in a `.env` file in the root of the repository, the test suite will automatically pick them up via `pytest-dotenv`, and it is ignored via `.gitignore`.

| Variable                                        | Description                                                                                                         |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| PYPICLOUD_ACCESS_GITHUB_TEST_MEMBER_USERNAME    | The username of the member user                                                                                     |
| PYPICLOUD_ACCESS_GITHUB_TEST_MEMBER_TOKEN       | The member user's personal access token                                                                             |
| PYPICLOUD_ACCESS_GITHUB_TEST_NONMEMBER_USERNAME | The username of the non-member user                                                                                 |
| PYPICLOUD_ACCESS_GITHUB_TEST_NONMEMBER_TOKEN    | The non-member user's personal access token                                                                         |
| PYPICLOUD_ACCESS_GITHUB_TEST_ADMIN_USERNAME     | The username of the admin user                                                                                      |
| PYPICLOUD_ACCESS_GITHUB_TEST_ADMIN_TOKEN        | The admin user's personal access token                                                                              |
| PYPICLOUD_ACCESS_GITHUB_TEST_ORGANIZATION       | The name of the Organization                                                                                        |
| PYPICLOUD_ACCESS_GITHUB_TEST_TOKEN              | The personal access token with admin access to the Organization                                                     |
| PYPICLOUD_ACCESS_GITHUB_TEST_ADDITIONAL_ADMINS  | A comma separated list of usernames that may also be members of the Organization, but won't be touched by the tests |

### Github Actions

To run the integration tests on Github Actions, you will need to set the corresponding *secrets* on the Github repository. The easiest way to do this is to fill out the `.env` file and run `make secrets-sync`.
