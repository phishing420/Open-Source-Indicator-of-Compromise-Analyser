import requests
import json
import sys
import re
from time import sleep
from datetime import datetime
from urllib.parse import urlparse
from config import URLSCAN_API_KEY, API_KEY, API_URL_Domain

def typing_effect(text: str, delay=0.015):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        sleep(delay)
    print()

def print_header(title: str, width=70):
    typing_effect(f"\n{'=' * width}")
    typing_effect(title.center(width))
    typing_effect(f"{'=' * width}")

def print_section(title: str):
    """Print subsection header"""
    typing_effect(f"\n{title.upper()}")
    typing_effect('-' * len(title))

def print_key_value(key: str, value: str, indent=0):
    typing_effect(f"{' ' * indent}{key:<20}: {value}")

def validate_url(url: str) -> bool:
    pattern = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(pattern, url) is not None

def fetch_virustotal_data(url: str) -> dict:
    """Fetch URL analysis from VirusTotal"""
    try:
        response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers={'x-apikey': API_KEY},
            data={'url': url},
            timeout=15
        )
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            return requests.get(analysis_url, headers={'x-apikey': API_KEY}, timeout=15).json()
        return {'error': f"VirusTotal API Error: HTTP {response.status_code}"}
    except Exception as e:
        return {'error': f"VirusTotal connection failed: {str(e)}"}

def submit_to_urlscan(url: str) -> str:
    """Submit URL to URLscan.io and return scan ID"""
    headers = {
        'API-Key': URLSCAN_API_KEY,
        'Content-Type': 'application/json'
    }
    data = {
        "url": url,
        "public": "on"
    }
    
    try:
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            json=data,
            timeout=15
        )
        response.raise_for_status()
        return response.json()['uuid']
    except Exception as e:
        return {'error': f"URLscan submission failed: {str(e)}"}

def get_urlscan_results(scan_id: str) -> dict:
    """Retrieve scan results from URLscan.io"""
    try:
        for _ in range(30):  # Max 30 attempts (5 minutes)
            response = requests.get(
                f'https://urlscan.io/api/v1/result/{scan_id}/',
                timeout=15
            )
            if response.status_code == 200:
                return response.json()
            sleep(10)
        return {'error': "Scan timed out after 5 minutes"}
    except Exception as e:
        return {'error': f"URLscan results failed: {str(e)}"}

def display_virustotal_results(data: dict, url: str):
    """Display VirusTotal URL analysis results"""
    if 'error' in data:
        print_section("VirusTotal Error")
        typing_effect(f"  {data['error']}")
        return

    attributes = data.get('data', {}).get('attributes', {})
    stats = attributes.get('stats', {})
    
    print_section("VirusTotal Analysis")
    print_key_value("URL", url)
    print_key_value("Scan Date", datetime.fromtimestamp(attributes.get('date', 0)).strftime('%Y-%m-%d %H:%M:%S'))
    
    # Detection stats
    print_section("Detection Stats")
    print_key_value("Malicious", stats.get('malicious', 0))
    print_key_value("Suspicious", stats.get('suspicious', 0))
    print_key_value("Harmless", stats.get('harmless', 0))
    print_key_value("Undetected", stats.get('undetected', 0))
    
    # Detailed detections
    print_section("Engine Detections")
    shown = 0
    results = attributes.get('results', {})
    for engine, result in results.items():
        if shown >= 5:
            break
        if result.get('category') in ['malicious', 'suspicious']:
            print_key_value(engine, result.get('result', 'Unknown'), 2)
            shown += 1

def display_urlscan_results(data: dict, url: str):
    """Display URLscan.io analysis results"""
    if 'error' in data:
        print_section("URLscan.io Error")
        typing_effect(f"  {data['error']}")
        return

    print_section("URLscan.io Analysis")
    print_key_value("URL", url)
    print_key_value("Scan ID", data.get('task', {}).get('uuid', 'N/A'))
    
    # Verdict information
    verdict = data.get('verdicts', {}).get('overall', {})
    print_section("Threat Assessment")
    print_key_value("Score", verdict.get('score', 0))
    print_key_value("Malicious", "Yes" if verdict.get('malicious') else "No")
    
    # Threat indicators
    threats = data.get('verdicts', {}).get('threats', [])
    if threats:
        print_section("Threat Indicators")
        for threat in threats[:3]:  # Show top 3 threats
            print_key_value(threat['category'], threat['description'], 2)
    
    # Security checks
    security = data.get('meta', {}).get('processors', {}).get('security', {})
    if security:
        print_section("Security Findings")
        for check, details in security.items():
            if details.get('score', 0) > 0:
                severity = "Critical" if details['score'] > 7 else "Warning"
                print_key_value(check, f"[{severity}] {details.get('description', 'N/A')}", 2)
    
    # Visual elements
    print_section("Visual Evidence")
    print_key_value("Screenshot", f"https://urlscan.io/screenshots/{data.get('task', {}).get('uuid', '')}.png")
    print_key_value("Full Report", data.get('task', {}).get('reportURL', 'N/A'))

def analyze_url(url: str = None):
    """Main URL analysis workflow"""
    try:
        if url is None:
            url = input("\nEnter URL to analyze: ").strip()
            if not url:
                typing_effect("ERROR: No URL provided!")
                return
            if not validate_url(url):
                typing_effect("ERROR: Invalid URL format!")
                return

        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        print_header(f"ANALYZING URL: {url}")
        
        # Fetch data from both sources
        typing_effect("\n[1/2] Querying VirusTotal...")
        vt_data = fetch_virustotal_data(url)
        sleep(1)  # Rate limiting
        
        typing_effect("[2/2] Querying URLscan.io...")
        scan_id = submit_to_urlscan(url)
        urlscan_data = get_urlscan_results(scan_id) if not isinstance(scan_id, dict) else scan_id
        
        # Display results
        print_header(f"ANALYSIS RESULTS FOR: {url}")
        display_virustotal_results(vt_data, url)
        display_urlscan_results(urlscan_data, url)
        
        # Generate final verdict
        print_header("SECURITY ASSESSMENT")
        vt_malicious = vt_data.get('data', {}).get('attributes', {}).get('stats', {}).get('malicious', 0) if not vt_data.get('error') else 0
        urlscan_malicious = urlscan_data.get('verdicts', {}).get('overall', {}).get('malicious', False) if not urlscan_data.get('error') else False
        
        if vt_malicious > 0 or urlscan_malicious:
            typing_effect("WARNING: MALICIOUS URL DETECTED!")
        else:
            typing_effect("URL APPEARS CLEAN")

    except KeyboardInterrupt:
        typing_effect("\nAnalysis cancelled by user")
    except Exception as e:
        typing_effect(f"FATAL ERROR: {str(e)}")

if __name__ == "__main__":
    analyze_url()
