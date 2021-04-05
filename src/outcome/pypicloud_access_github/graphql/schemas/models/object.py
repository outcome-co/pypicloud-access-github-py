"""Type definition."""

from __future__ import annotations

from typing import Literal, Union

from pydantic import BaseModel, Field


class BaseGitObject(BaseModel):
    ...


class BlobObject(BaseGitObject):
    typename: Literal['Blob'] = Field(..., alias='__typename')
    text: str


class TagObject(BaseGitObject):
    typename: Literal['Tag'] = Field(..., alias='__typename')
    target: GitObject


GitObject = Union[BlobObject, TagObject]
