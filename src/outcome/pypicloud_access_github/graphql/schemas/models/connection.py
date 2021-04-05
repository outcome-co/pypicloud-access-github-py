"""Type definition."""

from typing import Generic, Optional, Sequence, TypeVar

from outcome.pypicloud_access_github.graphql.schemas.models.page_info import PageInfo
from pydantic import BaseModel, Field
from pydantic.generics import GenericModel

E = TypeVar('E', bound=BaseModel)
N = TypeVar('N', bound=BaseModel)


class Connection(GenericModel, Generic[E, N]):
    edges: Optional[Sequence[E]]
    nodes: Optional[Sequence[N]]
    page_info: Optional[PageInfo] = Field(None, alias='pageInfo')
