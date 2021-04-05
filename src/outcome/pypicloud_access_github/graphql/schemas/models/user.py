"""Type definition."""

from pydantic import BaseModel


class User(BaseModel):
    login: str
