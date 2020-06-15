from outcome.pypicloud_access_github.graphql_schema import Query
from sgqlc.endpoint.http import HTTPEndpoint
from sgqlc.operation import Operation

_github_graphql_endpoint = 'https://api.github.com/graphql'
_default_page_size = 10


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
        return operation + data

    def get_pages(self, get_page_fn):
        page_context = PageContext()

        while page_context.has_next_page:
            get_page_fn(page_context)


class PageContext:
    def __init__(self):
        self.cursor = None
        self.has_next_page = True

    def paginate(self, edge_fn, **kwargs):
        page_args = self.page_args(after=self.cursor, **kwargs)
        edge = edge_fn(**page_args)
        edge.page_info.__fields__('has_next_page', 'end_cursor')

        return edge

    def page_args(self, **kwargs):
        if 'first' not in kwargs:
            kwargs['first'] = _default_page_size

        return {k: v for k, v in kwargs.items() if v}

    def update_from_page_info(self, edge):
        self.has_next_page = edge.page_info.has_next_page
        self.cursor = edge.page_info.end_cursor
