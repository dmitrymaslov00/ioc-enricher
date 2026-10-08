import re
import ipaddress
from urllib.parse import urlparse



def detect_ioc_type(value):
    value = value.strip()

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
