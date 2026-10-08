import json
import pytest
from ioc_enricher.__main__ import main 



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