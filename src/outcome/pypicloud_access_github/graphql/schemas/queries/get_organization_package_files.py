"""Type definition."""

from outcome.pypicloud_access_github.graphql.schemas.models.organization import Organization
from pydantic import BaseModel


class GetOrganizationPackageFiles(BaseModel):
    organization: Organization
