import sys
from ioc_enricher.parser import detect_ioc_type, refang, normalize
import argparse
import json
import os
from dotenv import load_dotenv
from ioc_enricher.providers.abuseipdb import check_ip
from pathlib import Path
from ioc_enricher.cache import Cache


CACHE_PATH = Path.home() / '.cache' / 'ioc-enricher' / 'cache.db'


def main(argv=None):

    parser = argparse.ArgumentParser(description='ioc enricher')
    parser.add_argument('input', help = 'path to the input file')
    parser.add_argument('-f', '--format', choices = ['tsv', 'json'], default = 'tsv', help = 'output format (default: tsv)')
    parser.add_argument('-e', '--enrich', action = 'store_true', help = 'look up ip addresses in AbuseIPDB (ABUSEIPDB_API_KEY required in .env file)')
    parser.add_argument('--no-cache', action = 'store_true', help = 'disable caching for AbuseIPDB API requests')
    args = parser.parse_args(argv)

    api_key = None
    cache = None

    if args.enrich:
        load_dotenv()
        api_key = os.environ.get('ABUSEIPDB_API_KEY')
        if not api_key:
            print('ABUSEIPDB_API_KEY not found in .env file', file=sys.stderr)
            return 1


    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            data = f.readlines()
    except FileNotFoundError:
        print(f'File {args.input} not found. Please, check the path and name of the file you provide', file=sys.stderr)
        return 1

    seen = set()
    results = []

    for line in data:
        clean = refang(line)
        if not clean or clean.startswith('#'):
            continue
        ioc = detect_ioc_type(clean)
        value = normalize(clean, ioc)

        key = (ioc, value)

        if key in seen:
            continue
        else:
            seen.add(key)
            results.append({ 'type': ioc, 'value': value })

    if args.enrich:
        if not args.no_cache:
            CACHE_PATH.parent.mkdir(parents = True, exist_ok = True)
            cache = Cache(CACHE_PATH)
        try:
            for i in results:
                if i["type"] in ('ipv4', 'ipv6'):
                    res = None
                    if cache:
                        res = cache.get('abuseipdb', i["value"])
                    if res is None:
                        res = check_ip(i["value"], api_key)
                        if cache and 'error' not in res:
                            cache.set('abuseipdb', i["value"], res)
                    i["abuseipdb"] = res
        finally:
            if cache:
                cache.close()

    if args.format == 'tsv':
        if not args.enrich:
            for i in results:
                print(f'{i["type"]}\t{i["value"]}')
        else:
            for i in results:
                info = i.get('abuseipdb')
                if not info:
                    score = ''
                    country = ''
                elif "error" in info:
                    score = 'error'
                    country = info["error"]
                else:
                    score = str(info["score"])
                    country = str(info["country"] or '')
                print(f'{i["type"]}\t{i["value"]}\t{score}\t{country}')

    elif args.format == 'json':
        print(json.dumps(results, indent=2, ensure_ascii=False))

    return 0

if __name__ == '__main__':
    sys.exit(main())
