import sys
from ioc_enricher.parser import detect_ioc_type, refang, normalize
import argparse
import json


def main(argv=None):

    parser = argparse.ArgumentParser(description='ioc enricher')
    parser.add_argument('input', help = 'path to the input file')
    parser.add_argument('-f', '--format', choices = ['tsv', 'json'], default = 'tsv', help = 'output format (default: tsv)')
    args = parser.parse_args(argv)

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

    if args.format == 'tsv':
        for i in results:
            print(f'{i["type"]}\t{i["value"]}')

    elif args.format == 'json':
        print(json.dumps(results, indent=2, ensure_ascii=False))

    return 0

if __name__ == '__main__':
    sys.exit(main())
