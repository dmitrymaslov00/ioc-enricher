import pytest
from ioc_enricher.cache import Cache



@pytest.fixture
def cache(tmp_path):
    cache = Cache(tmp_path / 'cache.db')
    yield cache
    cache.close()


def test_set_get(cache):
    data = {"score": 50, "reports": 222, "country": "DE", "isp": "Deutsche Telekom"}
    cache.set('abuseipdb', '8.8.8.8', data)

    assert cache.get('abuseipdb', '8.8.8.8') == data


def test_get_missing_returns_none(cache):
    assert cache.get('abuseipdb', '1.1.1.1') is None


def test_expired_entry_returns_none(tmp_path):
    cache = Cache(tmp_path / 'cache.db', ttl_seconds = 0)
    cache.set('abuseipdb', '8.8.8.8', {"score": 1})

    assert cache.get('abuseipdb', '8.8.8.8') is None
    cache.close()


def test_providers_dont_mix(cache):
    cache.set('abuseipdb', '8.8.8.8', {"score": 1})
    cache.set('virustotal', '8.8.8.8', {"score": 2})

    assert cache.get('abuseipdb', '8.8.8.8') == {"score": 1}
    assert cache.get('virustotal', '8.8.8.8') == {"score": 2}


def test_set_overwrites(cache):
    cache.set('abuseipdb', '8.8.8.8', {"score": 1})
    cache.set('abuseipdb', '8.8.8.8', {"score": 99})

    assert cache.get('abuseipdb', '8.8.8.8') == {"score": 99}


def test_cache_persists_between_instances(tmp_path):
    path = tmp_path / 'cache.db'
    c1 = Cache(path)
    c1.set('abuseipdb', '8.8.8.8', {"score": 7})
    c1.close()

    c2 = Cache(path)
    assert c2.get('abuseipdb', '8.8.8.8') == {"score": 7}
    c2.close()