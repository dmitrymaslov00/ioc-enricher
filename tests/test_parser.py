import pytest
from ioc_enricher.parser import detect_ioc_type, refang


@pytest.mark.parametrize('value, expected', [
    ('', 'unknown'),
    ('   ', 'unknown'),
    ('999.1.1.1', 'unknown'),
    ('1.2.3', 'unknown'),
    ('1.2.3.4.5', 'unknown'),
    ('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', 'unknown'),
    ('D41D8CD98F00B204E9800998ECF8427E', 'md5'),
    ('http://', 'unknown'),
    ('ftp://example.com', 'unknown'),
    ('localhost', 'unknown'),
    ('-bad.com', 'unknown'),
    ('hello world.txt', 'unknown'),
    ('a..b', 'unknown'),
    ('test.', 'unknown'),
    ('::1', 'ipv6'),
    ('Example.COM', 'domain'),
    ('http://:80', 'unknown'),
    ('hxxps://evil[.]com/a', 'url'),
    ('hxxp://evil[.]com', 'url'),
    ('1[.]2[.]3[.]4', 'ipv4'),
    ('evil[.]com', 'domain')
])

def test_detect_ioc_type(value, expected):
    assert detect_ioc_type(value) == expected


@pytest.mark.parametrize('value, expected', [
    ('hxxps://evil[.]com', 'https://evil.com'),
    ('hxxp://evil[.]com', 'http://evil.com'),
    ('1[.]2[.]3[.]4', '1.2.3.4'),
    ('evil(.)com', 'evil.com'),
    ('evil{.}com', 'evil.com'),
    ('hxxp[:]//evil.com', 'http://evil.com'),
    ('hxxp[://]evil.com', 'http://evil.com'),
    ('hxxps[:]//evil[.]com/path', 'https://evil.com/path'),
    ('HXXP://evil[.]com', 'http://evil.com'),
    ('HxxPS://evil[.]com', 'https://evil.com'),
    ('  evil[.]com  ', 'evil.com'),
    ('example.com', 'example.com'),
    ('https://example.com/a', 'https://example.com/a'),
    ('8.8.8.8', '8.8.8.8'),
    ('', ''),
    ('myhxxpsite.com', 'myhxxpsite.com'),
    ('evil.com/hxxp', 'evil.com/hxxp'),
])

def test_refang(value, expected):
    assert refang(value) == expected
