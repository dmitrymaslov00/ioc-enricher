# ioc-enricher

This CLI tool is designed for SOC analysts. The analyst receives a list of IOCs (Indicators of Compromise) from a report. Such lists are usually messy, contain duplicates, and include a lot of irrelevant data. The program strips whitespace, skips comments, restores defanged indicators, removes duplicates, normalizes (lowercases hosts and hashes) and identifies the IOC type for each unique string. For example the string `hxxps://evil[.]com` becomes `url https://evil.com`. Optionally, using the flag `-e/--enrich`, for IPv4 and IPv6 addresses it queries AbuseIPDB via its API and returns information about the IP addresses. 

## Features

- **Refang:** strips whitespace, converts `[.],(.),{.}` -> `.`, `[:]` -> `:`, `[://]` -> `://`. Also `hxxp(s)` becomes `http(s)`
- **Type detection:** `md5`, `sha1`, `sha256`, `ipv4`, `ipv6`, `url`, `domain`
- **Normalization:** lowercases hashes, domains, canonicalizes IPv6 addresses and lowercases the scheme and host of URLs (e.g `HTTPS://Evil.COM/Login` becomes `https://evil.com/Login`)
- **Deduplication:** removes duplicate entries after refang and normalization, so `EVIL.com` and `evil[.]com` count as one IOC
- **Output:** tsv (default) and json via `-f/--format`
- **Enrichment:** enabled by flag `-e/--enrich`. It looks up the information about IPv4 and IPv6 addresses via AbuseIPDB API

## Installation

```bash
git clone https://github.com/dmitrymaslov00/ioc-enricher.git
cd ioc-enricher
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

## Configuration

```bash
cp .env.example .env
```

To use enrichment (`-e/--enrich`) get a free API key at [abuseipdb.com](https://www.abuseipdb.com/) and then add `ABUSEIPDB_API_KEY=YOUR_API_KEY` into `.env` file. The key is not required if you don't use `-e/--enrich`.

## Usage

Note: `PYTHONPATH=src` is environment variable. It tells Python where to look for the package and is required until the project is packaged. 

Regular run in tsv format (output truncated): 

```bash
PYTHONPATH=src python3 -m ioc_enricher examples/iocs.txt
```
```text
ipv4    8.8.8.8
ipv4    185.220.101.45
ipv6    2001:db8::1
domain  evil-domain.com
url     https://malicious-site.example/payload.exe
md5     d41d8cd98f00b204e9800998ecf8427e
sha1    da39a3ee5e6b4b0d3255bfef95601890afd80709
```

Run with json output (without `-e/--enrich` IP addresses won't have AbuseIPDB data):

```bash
PYTHONPATH=src python3 -m ioc_enricher examples/test_ips.txt -f json
```
```text
[
  {
    "type": "ipv4",
    "value": "8.8.8.8"
  },
  {
    "type": "ipv4",
    "value": "1.1.1.1"
  }
]
```

Run with json output and enrichment:

```bash
PYTHONPATH=src python3 -m ioc_enricher examples/test_ips.txt -f json -e
```
```text
[
  {
    "type": "ipv4",
    "value": "8.8.8.8",
    "abuseipdb": {
      "score": 0,
      "reports": 237,
      "country": "US",
      "isp": "Google LLC"
    }
  },
  {
    "type": "ipv4",
    "value": "1.1.1.1",
    "abuseipdb": {
      "score": 0,
      "reports": 131,
      "country": "AU",
      "isp": "APNIC and Cloudflare DNS Resolver project"
    }
  }
]
```

Run with tsv output and enrichment (type, value, score, country):

```bash
PYTHONPATH=src python3 -m ioc_enricher examples/test_ips.txt -f tsv -e
```
```text
ipv4    8.8.8.8     0       US
ipv4    1.1.1.1     0       AU
```

## Design decisions

- `--enrich` is disabled by default to not spend your API limits. The network should not be switched on accidentally. Tests and default runs don't depend on an internet connection
- Errors go into stderr and output data into stdout. Stdout is data which can be transferred to another program and errors should not go into it
- Enrichment goes after deduplication not to repeat API requests on identical IP addresses and not waste limits (`31.16.188.104` and `31[.]16[.]188[.]104` count as one request, not two)
- `check_ip` function returns `{"error": "..."}` to recognize which exact error the program faced and give correct output next to the entry. It helps not to kill the whole process and continue processing other entries
- In enrichment tests real API requests are replaced with fake ones. It helps to avoid spending limits, network isn't required and errors can be reproduced artificially to check the program's responses

## Known limitations

- KeyError will be raised if AbuseIPDB API will give non-typical response
- Only IP addresses are enriched
- No cache saves between runs
- No retries in case of 429 error code
- `PYTHONPATH=src` is required

## Tests

```bash
pytest
```
```text
84 passed in 0.15s
```