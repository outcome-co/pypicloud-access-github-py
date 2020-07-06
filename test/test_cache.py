from unittest.mock import patch

import pytest
from dogpile.cache.api import NO_VALUE
from outcome.pypicloud_access_github import cache


def dummy_cached_fn(**kwargs):
    return True


class DummyClass:
    def dummy_cached_fn(self):
        return True


module = __name__


def test_key_generator_no_namespace():
    prefix = f'{module}:{dummy_cached_fn.__name__}|'
    generator = cache.cache_key_generator(namespace=None, fn=dummy_cached_fn)
    key = generator()

    assert key.startswith(prefix)


def test_key_generator_namespace():
    prefix = f'{module}:{dummy_cached_fn.__name__}|ns|'
    generator = cache.cache_key_generator(namespace='ns', fn=dummy_cached_fn)
    key = generator()

    assert key.startswith(prefix)


def test_key_generator_with_kwargs():
    generator = cache.cache_key_generator(namespace=None, fn=dummy_cached_fn)

    with pytest.raises(ValueError):
        generator(foo='bar')


def test_key_generator_strip_self():

    inst_a = DummyClass()
    inst_b = DummyClass()

    generator_a = cache.cache_key_generator(namespace=None, fn=inst_a.dummy_cached_fn)
    generator_b = cache.cache_key_generator(namespace=None, fn=inst_b.dummy_cached_fn)

    # Since the methods are bound to the instances, the first argument
    # is `self`, which should be different - we want to ensure we've
    # detected and removed the `self` arg from the key calculation
    assert generator_a(1) == generator_b(1)


@patch('outcome.pypicloud_access_github.cache.TTLCache', autospec=True)
def test_ttl_interface(mocked_ttlcache):
    init_args = {'maxsize': 100, 'ttl': 200}
    backend = cache.TTLBackend(init_args)

    mocked_ttlcache.assert_called_with(**init_args)

    key = 'key'
    value = 'value'

    backend.delete(key)
    backend.cache.pop.assert_called_with(key)
    backend.cache.reset_mock()

    backend.set(key, value)
    backend.cache.__setitem__.assert_called_with(key, value)
    backend.cache.reset_mock()

    backend.get(key)
    backend.cache.get.assert_called_with(key, NO_VALUE)
