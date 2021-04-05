"""Type definition."""

from outcome.pypicloud_access_github.graphql.schemas.models.user import User
from pydantic import BaseModel


class GetCurrentUser(BaseModel):
    viewer: User
