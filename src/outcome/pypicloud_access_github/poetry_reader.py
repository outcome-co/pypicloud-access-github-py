from typing import Optional

import toml
from github import ContentFile


def get_package_name(package_file: ContentFile.ContentFile) -> Optional[str]:
    try:
        file_toml = toml.loads(package_file.decoded_content.decode('utf-8'))
        return file_toml['tool']['poetry']['name']
    except Exception:
        return None
