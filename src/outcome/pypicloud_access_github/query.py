from sgqlc.endpoint.http import HTTPEndpoint
from sgqlc.operation import Operation

from outcome.pypicloud_access_github.graphql_schema import Query


_github_graphql_endpoint = 'https://api.github.com/graphql'


class Endpoint:

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            'Authorization': f'token {self.token}',
        }

        self.endpoint = HTTPEndpoint(_github_graphql_endpoint, self.headers)

    def operation(self) -> Operation:
        return Operation(Query)

    def execute(self, operation: Operation):
        data = self.endpoint(operation)
        return (operation + data)
