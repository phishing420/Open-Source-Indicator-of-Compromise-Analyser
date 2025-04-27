import requests
import json
import sys
from datetime import datetime
from time import sleep
from pathlib import Path
from config import API_KEY, ABUSE_CH_API_KEY

def typing_effect(text: str, delay=0.015):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        sleep(delay)
    print()

def print_header(title: str):
    typing_effect(f"\n{'=' * 50}")
    typing_effect(title.center(50))
    typing_effect(f"{'=' * 50}")

def print_section(title: str):
    typing_effect(f"\n{title.upper()}")
    typing_effect('-' * len(title))

def fetch_abusech_data(hash_value: str) -> dict:
    """Fetch hash analysis from abuse.ch API"""
    try:
        response = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': hash_value},
            timeout=15
        )
        return response.json() if response.status_code == 200 else {}
    except Exception as e:
        return {'error': f"abuse.ch connection failed: {str(e)}"}

def fetch_virustotal_data(hash_value: str) -> dict:
    """Fetch hash analysis from VirusTotal API"""
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers={"x-apikey": API_KEY},
            timeout=10
        )
        if response.status_code == 404:
            return {'error': 'Hash not found in VirusTotal database'}
        return response.json() if response.status_code == 200 else {}
    except Exception as e:
        return {'error': f"VirusTotal connection failed: {str(e)}"}

def analyze_hash(hash_value: str):
    """Main analysis workflow"""
    try:
        print_header("HASH ANALYSIS REPORT")
        typing_effect(f"\nTarget Hash: {hash_value}")

        errors = []
        vt_data = {}
        abusech_data = {}

        # Fetch data from both sources
        typing_effect("\nQuerying threat intelligence platforms...")
        vt_response = fetch_virustotal_data(hash_value)
        abusech_response = fetch_abusech_data(hash_value)

        # Process VirusTotal data
        if 'error' in vt_response:
            errors.append(vt_response['error'])
        else:
            vt_data = vt_response.get('data', {}).get('attributes', {})

        # Process abuse.ch data
        if 'error' in abusech_response:
            errors.append(abusech_response['error'])
        else:
            abusech_data = abusech_response

        # Show errors first
        if errors:
            print_section("Analysis Errors")
            for error in errors:
                typing_effect(f"• {error}")

        # VirusTotal Analysis
        if vt_data:
            print_section("VirusTotal Intelligence")
            typing_effect(f"File Type: {vt_data.get('type_description', 'Unknown')}")
            typing_effect(f"First Submitted: {datetime.fromtimestamp(vt_data.get('first_submission_date', 0))}")
            
            stats = vt_data.get('last_analysis_stats', {})
            typing_effect(f"\nDetection Summary:")
            typing_effect(f"Malicious: {stats.get('malicious', 0)}")
            typing_effect(f"Suspicious: {stats.get('suspicious', 0)}")
            typing_effect(f"Undetected: {stats.get('undetected', 0)}")

            print_section("Top Detections")
            shown = 0
            for engine, result in vt_data.get('last_analysis_results', {}).items():
                if shown >= 5:
                    break
                if result.get('category') in ['malicious', 'suspicious']:
                    typing_effect(f"{engine}: {result.get('result', 'Unknown')}")
                    shown += 1

        # Abuse.ch Analysis
        if abusech_data.get('query_status') == 'ok':
            print_section("abuse.ch Intelligence")
            abuse_info = abusech_data.get('data', [{}])[0]
            
            if abuse_info.get('signature'):
                typing_effect(f"Threat Name: {abuse_info['signature']}")
            if abuse_info.get('file_name'):
                typing_effect(f"Associated File: {abuse_info['file_name']}")
            if abuse_info.get('tags'):
                typing_effect(f"Threat Tags: {', '.join(abuse_info['tags'])}")
            if abuse_info.get('intelligence'):
                typing_effect(f"Intelligence Sources: {abuse_info['intelligence']}")
        elif abusech_data.get('query_status'):
            typing_effect(f"abuse.ch Status: {abusech_data['query_status']}")

        # Final Verdict
        print_header("FINAL ASSESSMENT")
        vt_malicious = vt_data.get('last_analysis_stats', {}).get('malicious', 0) > 0
        abusech_malicious = abusech_data.get('query_status') == 'ok'
        
        if vt_malicious or abusech_malicious:
            typing_effect("WARNING: MALICIOUS INDICATORS DETECTED!")
        else:
            typing_effect("NO KNOWN MALICIOUS ACTIVITY DETECTED")

    except KeyboardInterrupt:
        typing_effect("\nAnalysis cancelled by user")
    except Exception as e:
        typing_effect(f"Critical Error: {str(e)}")

def main():
    """CLI entry point"""
    try:
        hash_value = input("Enter hash to analyze (MD5/SHA1/SHA256): ").strip()
        if len(hash_value) not in [32, 40, 64]:
            typing_effect("Error: Invalid hash length (must be 32, 40, or 64 characters)")
            return
        
        analyze_hash(hash_value)
        
    except Exception as e:
        typing_effect(f"Initialization Error: {str(e)}")

if __name__ == "__main__":	
    analyze_hash()
