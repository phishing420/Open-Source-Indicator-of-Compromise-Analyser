import re
import os
import json
import sys
import requests
from time import sleep
from datetime import datetime
from urllib.parse import quote
from config import API_KEY, API_URL_Domain, URLSCAN_API_KEY

# Constants
MAX_RETRIES = 3
REQUEST_DELAY = 1  # seconds between API calls
CACHE_DIR = "cache/domains"
os.makedirs(CACHE_DIR, exist_ok=True)

def type_effect(text: str, delay=0.015):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        sleep(delay)
    print()

def print_header(title: str, width=70):
    type_effect(f"\n{'=' * width}")
    type_effect(title.center(width))
    type_effect(f"{'=' * width}")

def print_section(title: str):
    """Print subsection header"""
    type_effect(f"\n{title.upper()}")
    type_effect('-' * len(title))

def print_key_value(key: str, value: str, indent=0, max_width=80):
    prefix = ' ' * indent
    key_str = f"{prefix}{key:<20}: "
    value_str = str(value)
    
    if len(key_str + value_str) > max_width:
        type_effect(key_str)
        for line in [value_str[i:i+max_width-len(prefix)] for i in range(0, len(value_str), max_width-len(prefix))]:
            type_effect(f"{prefix}{' ' * 20}  {line}")
    else:
        type_effect(key_str + value_str)

def validate_domain(domain: str) -> bool:
    pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return re.match(pattern, domain, re.IGNORECASE) is not None

def fetch_with_retry(url: str, headers=None, retries=MAX_RETRIES):
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            if attempt == retries - 1:
                raise
            sleep(REQUEST_DELAY * (attempt + 1))
    return None

def fetch_domain_data(domain: str) -> dict:
    """Fetch domain analysis data from VirusTotal with caching"""
    cache_file = f"{CACHE_DIR}/{domain}.json"
    
    # Try cache first
    try:
        with open(cache_file) as f:
            cached = json.load(f)
            if (datetime.now() - datetime.fromisoformat(cached['timestamp'])).days < 1:
                return cached['data']
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass

    # Fetch fresh data
    try:
        url = f"{API_URL_Domain}{quote(domain)}"
        data = fetch_with_retry(url, headers={'x-apikey': API_KEY})
        
        # Cache the result
        with open(cache_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'data': data
            }, f)
        return data
    except Exception as e:
        return {'error': f"VirusTotal API Error: {str(e)}"}

def fetch_urlscan_data(domain: str) -> dict:
    """Fetch domain data from URLscan.io with comprehensive checks"""
    try:
        # Search for recent scans
        search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1"
        search_data = fetch_with_retry(
            search_url,
            headers={'API-Key': URLSCAN_API_KEY}
        )
        
        if not search_data.get('results'):
            return {'error': 'No historical scans found'}
        
        # Get the most recent result
        result_url = f"https://urlscan.io/api/v1/result/{search_data['results'][0]['task']['uuid']}/"
        result_data = fetch_with_retry(
            result_url,
            headers={'API-Key': URLSCAN_API_KEY}
        )
        
        # Enrich with screenshot if available
        if result_data.get('task', {}).get('screenshotURL'):
            result_data['screenshot'] = result_data['task']['screenshotURL']
        
        return result_data
    except Exception as e:
        return {'error': f"URLscan API Error: {str(e)}"}

def display_virustotal_results(data: dict):
    """Enhanced VirusTotal results display"""
    if 'error' in data:
        print_section("VirusTotal Error")
        type_effect(f"  {data['error']}")
        return

    attributes = data.get('data', {}).get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    
    print_section("VirusTotal Analysis")
    print_key_value("Domain", data['data']['id'])
    
    # Reputation analysis
    reputation = attributes.get('reputation', 0)
    if reputation < 0:
        rep_status = f"\033[91mSuspicious ({reputation})\033[0m"  # Red
    elif reputation > 50:
        rep_status = f"\033[92mTrusted ({reputation})\033[0m"   # Green
    else:
        rep_status = f"Neutral ({reputation})"
    print_key_value("Reputation", rep_status)
    
    # Detailed stats
    print_section("Detection Stats")
    for stat, count in stats.items():
        color_code = ""
        if stat == 'malicious' and count > 0:
            color_code = "\033[91m"  # Red
        elif stat == 'suspicious' and count > 0:
            color_code = "\033[93m"  # Yellow
        print_key_value(stat.title(), f"{color_code}{count}\033[0m", 2)

    # WHOIS information
    if attributes.get('whois'):
        print_section("WHOIS Summary")
        whois = attributes['whois'].split('\n')[:5]  # Show first 5 lines
        for line in whois:
            if line.strip():
                type_effect(f"  {line.strip()}")

def display_urlscan_results(data: dict):
    """Enhanced URLscan results display with threat intel"""
    if 'error' in data:
        print_section("URLscan Error")
        type_effect(f"  {data['error']}")
        return

    print_section("URLscan.io Analysis")
    
    # Threat indicators
    threats = data.get('verdicts', {}).get('threats', [])
    if threats:
        print_key_value("Threat Indicators", "")
        for threat in threats[:3]:  # Show top 3 threats
            print_key_value(f"  {threat['category']}", threat['description'], 2)
    
    # Security checks
    security = data.get('meta', {}).get('processors', {}).get('security', {})
    if security:
        print_section("Security Findings")
        for check, details in security.items():
            if details.get('score', 0) > 0:
                severity = "🔴 Critical" if details['score'] > 7 else "🟡 Warning"
                print_key_value(f"{severity} {check}", details.get('description', 'N/A'), 2)
    
    # Visual elements
    if data.get('screenshot'):
        print_section("Visual Evidence")
        type_effect(f"  Screenshot: {data['screenshot']}")
    if data.get('task', {}).get('reportURL'):
        type_effect(f"  Full Report: {data['task']['reportURL']}")

def analyze_domain(domain: str = None):
    """Main domain analysis workflow with optional domain parameter"""
    try:
        if domain is None:
            domain = input("\nEnter domain to analyze: ").strip().lower()
            if not domain:
                type_effect("ERROR: No domain entered!")
                return
            if not validate_domain(domain):
                type_effect("ERROR: Invalid domain format!")
                return

        print_header(f"ANALYZING: {domain.upper()}")
        
        # Fetch data with progress indication
        type_effect("\n[1/2] Querying VirusTotal...")
        vt_data = fetch_domain_data(domain)
        sleep(REQUEST_DELAY)
        
        type_effect("[2/2] Querying URLscan.io...")
        urlscan_data = fetch_urlscan_data(domain)
        
        # Display results
        print_header(f"RESULTS FOR: {domain.upper()}")
        display_virustotal_results(vt_data)
        display_urlscan_results(urlscan_data)
        
        # Generate verdict
        print_header("SECURITY ASSESSMENT")
        vt_malicious = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) if not vt_data.get('error') else 0
        urlscan_threats = len(urlscan_data.get('verdicts', {}).get('threats', [])) if not urlscan_data.get('error') else 0
        
        if vt_malicious > 3 or urlscan_threats > 1:
            type_effect("\033[91mHIGH RISK: Malicious activity detected\033[0m")
        elif vt_malicious > 0 or urlscan_threats > 0:
            type_effect("\033[93mMODERATE RISK: Suspicious indicators found\033[0m")
        else:
            type_effect("\033[92mLOW RISK: No malicious activity detected\033[0m")
            
    except KeyboardInterrupt:
        type_effect("\nAnalysis cancelled by user")
    except Exception as e:
        type_effect(f"Fatal Error: {str(e)}")

if __name__ == "__main__":
    analyze_domain()
