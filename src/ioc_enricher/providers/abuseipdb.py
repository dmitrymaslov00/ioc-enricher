import time

import requests

URL = 'https://api.abuseipdb.com/api/v2/check'
MAX_AGE_DAYS = 90


def check_ip(ip, api_key):
    params = {"ipAddress": ip, "maxAgeInDays":  MAX_AGE_DAYS}
    headers = {"Key": api_key, "Accept": "application/json"}

    for attempt in range(1, 4):
        try:
            r = requests.get(URL, params=params, headers=headers, timeout=5)

            if r.status_code == 429:
                if attempt == 3:
                    return {"error": "AbuseIPDB rate limit exceeded after 3 attempts"}
                
                time.sleep(attempt)
                continue

            if r.status_code == 200:
                payload = r.json()

                if "data" not in payload:
                    return {"error": "Incomplete AbuseIPDB response"}

                data = payload["data"]

                if "abuseConfidenceScore" not in data or "totalReports" not in data or "countryCode" not in data or "isp" not in data:
                    return {"error": "Incomplete AbuseIPDB response"}

                formatted_data = {
                    "score": data["abuseConfidenceScore"], 
                    "reports": data["totalReports"], 
                    "country": data["countryCode"], 
                    "isp": data["isp"]
                }
                
                return formatted_data
            elif r.status_code == 401:
                return {"error": "Bad API key"}
            elif r.status_code == 403:
                return {"error": "Forbidden"}
            elif r.status_code == 404:
                return {"error": "Not found"}
            elif r.status_code == 422:
                return {"error": "IP address is incorrect"}
            elif r.status_code == 500:
                return {"error": "API host is down"}
            elif r.status_code == 503:
                return {"error": "API host is unreachable"}
            else:
                return {"error": "Check your request or settings and try again"}

        except requests.exceptions.RequestException:
            return {"error": "Network error: check your internet connection"}