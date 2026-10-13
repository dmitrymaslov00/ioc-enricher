import sys
from ioc_enricher.parser import detect_ioc_type, refang, normalize
import argparse
import json
import os
from dotenv import load_dotenv
from ioc_enricher.providers.abuseipdb import check_ip


def main(argv=None):

    parser = argparse.ArgumentParser(description='ioc enricher')
    parser.add_argument('input', help = 'path to the input file')
    parser.add_argument('-f', '--format', choices = ['tsv', 'json'], default = 'tsv', help = 'output format (default: tsv)')
    parser.add_argument('-e', '--enrich', action = 'store_true', help = 'look up ip addresses in AbuseIPDB (ABUSEIPDB_API_KEY required in .env file)')
    args = parser.parse_args(argv)

    api_key = None
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
        for i in results:
            if i['type'] in ('ipv4', 'ipv6'):
                i['abuseipdb'] = check_ip(i['value'], api_key)

    if args.format == 'tsv':
        for i in results:
            print(f'{i["type"]}\t{i["value"]}')

    elif args.format == 'json':
        print(json.dumps(results, indent=2, ensure_ascii=False))

    return 0

if __name__ == '__main__':
    sys.exit(main())
