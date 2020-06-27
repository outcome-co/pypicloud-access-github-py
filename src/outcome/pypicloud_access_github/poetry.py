"""Subclass of Access to handle pyproject.toml files with poetry metadata."""

from typing import Optional

import toml
from outcome.pypicloud_access_github.access import Access

_pyproject = 'pyproject.toml'


class Poetry(Access):  # pragma: only-covered-in-integration-tests
    def get_package_name(self, package_file_content: str) -> Optional[str]:
        try:
            file_toml = toml.loads(package_file_content)
            return file_toml['tool']['poetry']['name']
        except Exception:
            return None

    @property
    def package_file_name(self) -> str:
        return _pyproject
