"""Type definition."""

from typing import Generic, TypeVar

from pydantic import BaseModel
from pydantic.generics import GenericModel

N = TypeVar('N', bound=BaseModel)


class Edge(GenericModel, Generic[N]):
    node: N
