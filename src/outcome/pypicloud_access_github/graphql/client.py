"""GraphQL client."""

import pydash
from outcome.pypicloud_access_github.graphql.schema import Query
from sgqlc.endpoint.http import HTTPEndpoint
from sgqlc.operation import Operation

_github_graphql_endpoint = 'https://api.github.com/graphql'
_default_page_size = 100


class Client:  # pragma: only-covered-in-integration-tests
    def __init__(self, token: str) -> None:
        self.token = token
        self.headers = {
            'Authorization': f'token {self.token}',
        }

        self.endpoint = HTTPEndpoint(_github_graphql_endpoint, self.headers)

    def operation(self) -> Operation:
        return Operation(Query)

    def execute(self, operation: Operation) -> Query:
        data = self.endpoint(operation)
        return operation + data

    def get(self, operation: Operation) -> Query:
        return self.execute(operation)

    def get_all(self, operation: Operation, page_on: str, **kwargs) -> Query:
        edges_path = f'{page_on}.edges'
        page_on_object = pydash.get(operation, page_on)

        # Ensure we fetch the page_info
        page_on_object.page_info.__fields__('has_next_page', 'end_cursor')
        page_on_object.__args__.update(kwargs)

        # Ensure we have a `first` value
        if 'first' not in page_on_object.__args__:
            page_on_object.__args__['first'] = _default_page_size

        has_pages = True
        result = None

        while has_pages:
            data = self.get(operation)
            page_on_result = pydash.get(data, page_on)

            has_pages = page_on_result.page_info.has_next_page
            page_on_object.__args__['after'] = page_on_result.page_info.end_cursor

            if result:
                pydash.get(result, edges_path).extend(pydash.get(data, edges_path))
            else:
                result = data
                pydash.get(result, page_on).page_info = None

        return result
