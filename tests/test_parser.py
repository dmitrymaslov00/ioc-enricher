import pytest
from ioc_enricher.parser import detect_ioc_type, refang, normalize


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


@pytest.mark.parametrize('value, ioc_type, expected', [
    ('D41D8CD98F00B204E9800998ECF8427E', 'md5',
     'd41d8cd98f00b204e9800998ecf8427e'),
    ('DA39A3EE5E6B4B0D3255BFEF95601890AFD80709', 'sha1',
     'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
    ('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855', 'sha256',
     'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    ('d41d8cd98f00b204e9800998ecf8427e', 'md5',
     'd41d8cd98f00b204e9800998ecf8427e'),
    ('Evil.COM', 'domain', 'evil.com'),
    ('Sub.Example.Co.UK', 'domain', 'sub.example.co.uk'),
    ('evil.com', 'domain', 'evil.com'),
    ('8.8.8.8', 'ipv4', '8.8.8.8'),
    ('2001:DB8:0:0:0:0:0:1', 'ipv6', '2001:db8::1'),
    ('2001:db8::1', 'ipv6', '2001:db8::1'),
    ('::1', 'ipv6', '::1'),
    ('https://Evil.COM/Path', 'url', 'https://evil.com/Path'),
    ('HTTPS://Evil.COM/Path', 'url', 'https://evil.com/Path'),
    ('https://Evil.COM:8443/Path', 'url', 'https://evil.com:8443/Path'),
    ('https://evil.com/a?Q=B', 'url', 'https://evil.com/a?Q=B'),
    ('https://evil.com/a?Q=B#Frag', 'url', 'https://evil.com/a?Q=B#Frag'),
    ('http://evil.com', 'url', 'http://evil.com'),
    ('hello world', 'unknown', 'hello world'),
    ('Hello.World', 'unknown', 'Hello.World'),
])
def test_normalize(value, ioc_type, expected):
    assert normalize(value, ioc_type) == expected


@pytest.mark.xfail(reason='netloc.lower() breaks register of login and password in URL')
def test_normalize_url_keeps_credentials_case():
    assert normalize('https://User:Pass@Evil.COM/a', 'url') == 'https://User:Pass@evil.com/a'