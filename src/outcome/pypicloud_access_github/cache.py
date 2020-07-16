"""Caching functions for the Github Auth module."""

import hashlib
import logging
from typing import Any, Dict

from cachetools import TTLCache
from dogpile.cache import CacheRegion, make_region, register_backend
from dogpile.cache.api import NO_VALUE, CacheBackend
from dogpile.cache.util import compat

LOG = logging.getLogger(__name__)


def get_cache_region():
    return make_region(function_key_generator=cache_key_generator)


# This is a copy of the default key generator from dogpile, but
# with additional hashing to avoid using sensitive values as cache keys
def cache_key_generator(namespace, fn, to_str=compat.string_type):
    if namespace is None:
        namespace = f'{fn.__module__}:{fn.__name__}'
    else:
        namespace = f'{fn.__module__}:{fn.__name__}|{namespace}'

    # Remove the `self` argument, since it'll always change
    fn_args = compat.inspect_getargspec(fn)
    has_self = fn_args[0] and fn_args[0][0] in {'self', 'cls'}

    def generate_key(*args, **kw):
        if kw:
            raise ValueError('The dogpile.cache default key creation function does not accept keyword arguments.')
        if has_self:
            args = args[1:]

        # Encode the args since they may be sensitive
        arg_key = hashlib.sha224(''.join(map(to_str, args)).encode('utf-8')).hexdigest()
        return f'{namespace}|{arg_key}'

    return generate_key


_default_cache_backend = 'memory'
# Expiration is dogpile's expiration TTL
_default_expiration = 300

_default_cache_size = 100

# The Cache TTL is the underlying backend TTL, which should
# be greater than dogpile's
# https://dogpilecache.sqlalchemy.org/en/latest/api.html#memcached-backends
_default_cache_ttl = _default_expiration * 1.5  # noqa: WPS432

# This gives us shortcuts to the actual modules
_backend_map = {
    'memory': _default_cache_backend,
    'memcache': 'dogpile.cache.memcached',
}

# Default settings
_default_backend_args = {
    'memory': {'maxsize': _default_cache_size, 'ttl': _default_cache_ttl},
    'memcache': {'url': '127.0.0.1', 'distributed_lock': True},
}


def configure_cache_region(cache_region: CacheRegion, settings: Dict[str, Any], prefix: str):
    backend_key = f'{prefix}.backend'
    expiration_key = f'{prefix}.expiration'

    # Determine the backend
    backend = settings.get(backend_key, _default_cache_backend)
    expiration = int(settings.get(expiration_key, _default_expiration))

    # Find all the args that make sense for the backend
    backend_arg_prefix = f'{prefix}.{backend}.'
    backend_args = {k[len(backend_arg_prefix) :]: v for k, v in settings.items() if k.startswith(backend_arg_prefix)}

    resolved_args = {**_default_backend_args[backend], **backend_args}

    LOG.info(f'Configuring cache region with {backend} backend, with settings {resolved_args}')

    # Configure the cache region
    cache_region.configure(
        _backend_map[backend], expiration_time=expiration, arguments=resolved_args, replace_existing_backend=True,
    )


class TTLBackend(CacheBackend):
    def __init__(self, arguments):
        self.cache = TTLCache(**arguments)

    def get(self, key):
        return self.cache.get(key, NO_VALUE)

    def set(self, key, value):  # noqa: WPS125, A003
        self.cache[key] = value

    def delete(self, key):
        self.cache.pop(key)


register_backend(_default_cache_backend, __name__, TTLBackend.__name__)
