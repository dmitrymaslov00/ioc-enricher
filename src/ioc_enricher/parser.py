import re
import ipaddress
from urllib.parse import urlparse


def refang(value):
    value = value.strip()

    if '[.]' in value:
        value = value.replace('[.]', '.')
    if '(.)' in value:
        value = value.replace('(.)', '.')
    if '{.}' in value:
        value = value.replace('{.}', '.')
    if '[:]' in value:
        value = value.replace('[:]', ':')
    if '[://]' in value:
        value = value.replace('[://]', '://') 

    value = re.sub(r'^hxxp', 'http', value, flags=re.IGNORECASE)
    value = re.sub(r'^https', 'https', value, flags=re.IGNORECASE)

    return value


def detect_ioc_type(value):
    value = refang(value)

    # hashes
    if len(value) == 32 and all(c in '0123456789abcdefABCDEF' for c in value):
        return 'md5'
    if len(value) == 40 and all(c in '0123456789abcdefABCDEF' for c in value):
        return 'sha1'
    if len(value) == 64 and all(c in '0123456789abcdefABCDEF' for c in value):
        return 'sha256'

    # ipv4&ipv6
    try:
        ip = ipaddress.ip_address(value)
        if ip.version == 4:
            return 'ipv4'
        elif ip.version == 6:
            return 'ipv6'
    except ValueError:
        pass

    # url
    url_data = urlparse(value)
    if url_data.scheme in ('http', 'https') and url_data.hostname:
        return 'url'

    # domain
    if re.fullmatch(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', value):
        return 'domain'


    return 'unknown'

def normalize(value, ioc_type):
    if ioc_type in ('md5', 'sha1', 'sha256', 'domain'):
        value = value.lower()

    if ioc_type in ('ipv4', 'ipv6'):
        value = str(ipaddress.ip_address(value))

    if ioc_type == 'url':
        u = urlparse(value)

        port = None
        try:
            port = u.port
        except ValueError:
            return value

        netloc = ''
        if u.username:
            netloc += f'{u.username}'
            if u.password:
                netloc += f':{u.password}'
            netloc += '@'
        if ':' in u.hostname:
            netloc += f'[{u.hostname}]'
        else:
            netloc += u.hostname
        if port is not None:
            netloc += f':{port}'

        value = u._replace(netloc=netloc).geturl()

    return value