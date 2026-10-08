import pytest
from ioc_enricher.parser import detect_ioc_type


@pytest.mark.parametrize('value, expected', [
    ('', 'unknown'),
    ('   ', 'unknown'),
    ('999.1.1.1', 'unknown'),
    ('1.2.3', 'unknown'),
    ('1.2.3.4.5', 'unknown'),
    ('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', 'unknown'),   # 32 символа, но не hex
    ('D41D8CD98F00B204E9800998ECF8427E', 'md5'),       # верхний регистр
    ('http://', 'unknown'),
    ('ftp://example.com', 'unknown'),
    ('localhost', 'unknown'),
    ('-bad.com', 'unknown'),
    ('hello world.txt', 'unknown'),
    ('a..b', 'unknown'),
    ('test.', 'unknown'),
    ('::1', 'ipv6'),
    ('Example.COM', 'domain'),
    ('http://:80', 'unknown')
])

def test_detect_ioc_type(value, expected):
    assert detect_ioc_type(value) == expected

