import requests


URL = 'https://api.abuseipdb.com/api/v2/check'
MAX_AGE_DAYS = 90


def check_ip(ip, api_key):
    params = {"ipAddress": ip, "maxAgeInDays":  MAX_AGE_DAYS}
    headers = {"Key": api_key, "Accept": "application/json"}

    try:
        r = requests.get(URL, params=params, headers=headers, timeout=5)

        if r.status_code == 200:
            data = r.json()["data"]

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
        elif r.status_code == 429:
            return {"error": "Too many requests"}
        elif r.status_code == 500:
            return {"error": "API host is down"}
        elif r.status_code == 503:
            return {"error": "API host is unreachable"}
        else:
            return {"error": "Check your request or settings and try again"}

    except requests.exceptions.RequestException:
        return {"error": "Network error: check your internet connection"}
