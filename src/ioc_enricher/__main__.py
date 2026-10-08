import sys
from ioc_enricher.parser import detect_ioc_type, refang, normalize
import argparse


def main(argv=None):

    parser = argparse.ArgumentParser(description='ioc enricher')
    parser.add_argument('input', help = 'path to the input file')
    args = parser.parse_args(argv)

    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            data = f.readlines()
    except FileNotFoundError:
        print(f'File {args.input} not found. Please, check the path and name of the file you provide', file=sys.stderr)
        return 1

    seen = set()

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

        print(f'{ioc}\t{value}')

    return 0

if __name__ == '__main__':
    sys.exit(main())
