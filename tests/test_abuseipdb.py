import responses
from ioc_enricher.providers.abuseipdb import check_ip, URL
import pytest
import requests



@responses.activate
def test_check_ip_success():
    responses.add(
        responses.GET,
        URL,
        json={"data": {"abuseConfidenceScore": 0, "totalReports": 234, "countryCode": "US", "isp": "Google LLC"}},
        status=200
    )

    res = check_ip('8.8.8.8', 'fake-key')

    assert res == {"score": 0, 
                    "reports": 234, 
                    "country": "US", 
                    "isp": "Google LLC"}



@pytest.mark.parametrize('status, expected_error', [
    (401, {"error": "Bad API key"}),
    (403, {"error": "Forbidden"}),
    (404, {"error": "Not found"}),
    (422, {"error": "IP address is incorrect"}),      
    (429, {"error": "Too many requests"}),
    (500, {"error": "API host is down"}),
    (503, {"error": "API host is unreachable"}),
    (444, {"error": "Check your request or settings and try again"})
])
@responses.activate
def test_check_errors(status, expected_error):
    responses.add(responses.GET, URL, status=status)
    assert check_ip('8.8.8.8', 'fake-key') == expected_error



@responses.activate
def test_check_network_error():
    responses.add(responses.GET, URL, body=requests.exceptions.ConnectionError())

    res = check_ip('8.8.8.8', 'fake-key')

    assert res == {"error": "Network error: check your internet connection"}