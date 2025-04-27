import json
import urllib.request
import urllib.parse
import requests
import ipaddress
from datetime import datetime
from time import sleep
import sys
from config import API_KEY, API_URL_Ip, ABUSEIPDB_API_KEY, ABUSE_CH_API_KEY

def typing_effect(text: str, delay=0.015):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        sleep(delay)
    print()

def print_header(title: str, width=70):
    """Print formatted section header"""
    typing_effect(f"\n{'=' * width}")
    typing_effect(title.center(width))
    typing_effect(f"{'=' * width}")

def print_section(title: str): 
    typing_effect(f"\n{title.upper()}")
    typing_effect('-' * len(title))

def print_key_value(key: str, value: str, indent=0):
    """Print formatted key-value pair"""
    typing_effect(f"{' ' * indent}{key:<20}: {value}")

def fetch_abuseipdb_data(ip: str) -> dict:
    """Fetch IP analysis from AbuseIPDB"""
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            },
            params={
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': True
            },
            timeout=15
        )
        if response.status_code == 200:
            return response.json().get('data', {})
        return {'error': f"AbuseIPDB API Error: HTTP {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': f"AbuseIPDB connection failed: {str(e)}"}

def fetch_abusech_data(ip: str) -> dict:
    """Fetch IP analysis from abuse.ch ThreatFox"""
    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={
                'query': 'search_ioc',
                'search_term': ip
            },
            timeout=15
        )
        if response.status_code == 200:
            return response.json()
        return {'error': f"ThreatFox API Error: HTTP {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': f"ThreatFox connection failed: {str(e)}"}

def fetch_virustotal_data(ip: str) -> dict:
    """Fetch IP analysis from VirusTotal"""
    try:
        url = API_URL_Ip + urllib.parse.quote(ip)
        request = urllib.request.Request(
            url,
            headers={'x-apikey': API_KEY}
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        return {'error': f"VirusTotal API Error: {e.code} {e.reason}"}
    except Exception as e:
        return {'error': f"VirusTotal connection failed: {str(e)}"}

def display_virustotal_results(data: dict):
    """Display detailed VirusTotal results"""
    if 'error' in data:
        print_section("VirusTotal Error")
        typing_effect(f"  {data['error']}")
        return

    attributes = data.get('data', {}).get('attributes', {})
    
    print_section("VirusTotal Analysis")
    print_key_value("IP Address", data['data']['id'])
    
    # Network information
    print_section("Network Information")
    print_key_value("ASN", attributes.get('asn', 'N/A'))
    print_key_value("AS Owner", attributes.get('as_owner', 'N/A'))
    print_key_value("Country", attributes.get('country', 'N/A'))
    print_key_value("Network", attributes.get('network', 'N/A'))
    
    # Reputation and analysis
    print_section("Reputation Analysis")
    print_key_value("Reputation Score", attributes.get('reputation', 'N/A'))
    
    stats = attributes.get('last_analysis_stats', {})
    print_key_value("Malicious Detections", stats.get('malicious', 0))
    print_key_value("Suspicious Detections", stats.get('suspicious', 0))
    print_key_value("Harmless Detections", stats.get('harmless', 0))
    print_key_value("Undetected", stats.get('undetected', 0))
    
    # Detailed detections
    print_section("Top Detections")
    shown = 0
    for engine, result in attributes.get('last_analysis_results', {}).items():
        if shown >= 5:
            break
        if result.get('category') in ['malicious', 'suspicious']:
            print_key_value(engine, result.get('result', 'Unknown'), 2)
            shown += 1

def display_abuseipdb_results(data: dict):
    """Display detailed AbuseIPDB results"""
    if 'error' in data:
        print_section("AbuseIPDB Error")
        typing_effect(f"  {data['error']}")
        return

    print_section("AbuseIPDB Analysis")
    print_key_value("Abuse Confidence", f"{data.get('abuseConfidenceScore', 0)}%")
    print_key_value("Total Reports", data.get('totalReports', 0))
    print_key_value("Last Reported", data.get('lastReportedAt', 'Never'))
    
    # ISP information
    print_section("ISP Details")
    print_key_value("ISP", data.get('isp', 'N/A'))
    print_key_value("Domain", data.get('domain', 'N/A'))
    print_key_value("Hostnames", ', '.join(data.get('hostnames', [])) or 'N/A')
    print_key_value("Usage Type", data.get('usageType', 'N/A'))
    
    # Recent reports
    if data.get('reports'):
        print_section("Recent Reports")
        for report in data.get('reports', [])[:3]:  # Show top 3 reports
            print_key_value(
                report.get('reportedAt', ''),
                f"{report.get('comment', 'No comment')} ({report.get('categories', ['Unknown'])[0]})",
                2
            )

def display_abusech_results(data: dict):
    """Display detailed abuse.ch ThreatFox results"""
    if 'error' in data:
        print_section("ThreatFox Error")
        typing_effect(f"  {data['error']}")
        return

    print_section("ThreatFox Analysis")
    if data.get('query_status') == 'ok':
        for ioc in data.get('data', [])[:3]:  # Show top 3 IOCs
            print_key_value("Threat Type", ioc.get('ioc_type', 'N/A'))
            print_key_value("Malware", ioc.get('malware', 'N/A'))
            print_key_value("First Seen", ioc.get('first_seen', 'N/A'))
            print_key_value("Last Seen", ioc.get('last_seen', 'N/A'))
            print_key_value("Confidence Level", ioc.get('confidence_level', 'N/A'))
            typing_effect("")  # Add empty line between entries
    else:
        typing_effect("No known malicious activity found")

def analyze_ip(ip: str = None):
    """Main IP analysis workflow (now accepts optional IP parameter)"""
    try:
        if ip is None:
            ip = input("\nEnter IP address to analyze: ").strip()
        
        # Validate IP address
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            typing_effect("Warning: This is a private IP address (not routable on public internet)")

        print_header(f"ANALYZING IP: {ip}")
        
        # Fetch data from all sources
        typing_effect("\n[1/3] Querying VirusTotal...")
        vt_data = fetch_virustotal_data(ip)
        sleep(1)  # Rate limiting
        
        typing_effect("[2/3] Querying AbuseIPDB...")
        abuseipdb_data = fetch_abuseipdb_data(ip)
        sleep(1)  # Rate limiting
        
        typing_effect("[3/3] Querying ThreatFox...")
        abusech_data = fetch_abusech_data(ip)
        
        # Display results
        print_header(f"ANALYSIS RESULTS FOR: {ip}")
        display_virustotal_results(vt_data)
        display_abuseipdb_results(abuseipdb_data)
        display_abusech_results(abusech_data)
        
        # Generate final verdict
        print_header("SECURITY ASSESSMENT")
        vt_malicious = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) if not vt_data.get('error') else 0
        abuse_score = abuseipdb_data.get('abuseConfidenceScore', 0) if not abuseipdb_data.get('error') else 0
        abusech_malicious = 1 if abusech_data.get('query_status') == 'ok' and not abusech_data.get('error') else 0
        
        if vt_malicious > 3 or abuse_score > 85:
            typing_effect("\033[91mHIGH RISK: Malicious activity confirmed\033[0m")
        elif vt_malicious > 0 or abuse_score > 50 or abusech_malicious:
            typing_effect("\033[93mMODERATE RISK: Suspicious indicators found\033[0m")
        else:
            typing_effect("\033[92mLOW RISK: No malicious activity detected\033[0m")

    except ValueError:
        typing_effect("ERROR: Invalid IP address format")
    except KeyboardInterrupt:
        typing_effect("\nAnalysis cancelled by user")
    except Exception as e:
        typing_effect(f"FATAL ERROR: {str(e)}")

if __name__ == "__main__":
    analyze_ip()
