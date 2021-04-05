"""Type definition."""

from typing import Optional

from pydantic import BaseModel, Field


class PageInfo(BaseModel):
    end_cursor: Optional[str] = Field(..., alias='endCursor')
    has_next_page: bool = Field(..., alias='hasNextPage')
