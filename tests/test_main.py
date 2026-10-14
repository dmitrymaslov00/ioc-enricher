import json
import pytest
from ioc_enricher.__main__ import main 
import responses
from ioc_enricher.providers.abuseipdb import URL


def test_basic(tmp_path, capsys):
    p = tmp_path / 'iocs.txt'
    p.write_text('8.8.8.8\n', encoding='utf-8')

    code = main([str(p)])
    out = capsys.readouterr().out

    assert code == 0
    assert 'ipv4\t8.8.8.8' in out


def test_duplicates(tmp_path, capsys):
    p = tmp_path / 'iocs.txt'
    p.write_text('EVIL.com\nevil.com\nevil[.]com', encoding='utf-8')

    code = main([str(p)])
    out = capsys.readouterr().out

    assert code == 0
    assert out.count('domain\tevil.com') == 1


def test_comments_and_blank_lines(tmp_path, capsys):
    p = tmp_path / 'iocs.txt'
    p.write_text('#hello\n \n  #2nd\n8.8.8.8', encoding = 'utf-8')

    code = main([str(p)])
    out = capsys.readouterr().out

    assert code == 0
    assert out.splitlines() == ['ipv4\t8.8.8.8']


def test_missing_file(tmp_path, capsys):
    p = tmp_path / 'nope.txt'

    code = main([str(p)])
    captured = capsys.readouterr()

    assert code == 1
    assert captured.err
    assert captured.out == ''


def test_json_output(tmp_path, capsys):
    p = tmp_path / 'iocs.txt'
    p.write_text('8.8.8.8\nevil[.]com', encoding = 'utf-8')

    code = main([str(p), '-f', 'json'])
    captured = capsys.readouterr()

    result = json.loads(captured.out)

    assert code == 0
    assert result == [{ "type": "ipv4", "value": "8.8.8.8" }, { "type": "domain", "value": "evil.com" }]


def test_invalid_format(tmp_path):
    p = tmp_path / 'iocs.txt'

    with pytest.raises(SystemExit) as exc_info:
        main([str(p), '-f', 'xml'])

    assert exc_info.value.code == 2


def test_enrich_without_key(tmp_path, capsys, monkeypatch):
    p = tmp_path / 'iocs.txt'
    p.write_text('8.8.8.8', encoding = 'utf-8')

    monkeypatch.delenv('ABUSEIPDB_API_KEY', raising=False)
    monkeypatch.setattr('ioc_enricher.__main__.load_dotenv', lambda: None)

    code = main([str(p), '--enrich'])
    captured = capsys.readouterr()

    assert code == 1
    assert captured.err
    assert captured.out == '' 


@responses.activate
def test_enrich_json(tmp_path, capsys, monkeypatch):
    p = tmp_path / 'iocs.txt'
    p.write_text('31.16.188.104\n31[.]16[.]188[.]104\nexample.com', encoding = 'utf-8')
    
    monkeypatch.setenv('ABUSEIPDB_API_KEY', 'fake-key')
    monkeypatch.setattr('ioc_enricher.__main__.load_dotenv', lambda: None)

    responses.add(
            responses.GET,
            URL,
            json={"data": {"abuseConfidenceScore": 50, "totalReports": 222, "countryCode": "DE", "isp": "Deutsche Telekom"}},
            status=200
        )

    code = main([str(p), '--enrich', '-f', 'json'])
    captured = capsys.readouterr()

    res = json.loads(captured.out)

    assert code == 0
    assert res == [
        {"type": "ipv4", "value": "31.16.188.104", "abuseipdb": {"score": 50, "reports": 222, "country": "DE", "isp": "Deutsche Telekom"}},
        {"type": "domain", "value": "example.com"}
    ]
    assert len(responses.calls) == 1