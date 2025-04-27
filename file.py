import requests
import json
import sys
import os
import yara
from time import sleep
from pathlib import Path
from config import API_KEY

def typing_effect(words: str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    print()

def print_bold(text: str):
    """Print text in bold"""
    print(f"\033[1m{text}\033[0m")

# Hidden YARA integration (no output changes)
YARA_RULES_DIR = "yara_rules"

def _load_yara_rules():
    try:
        Path(YARA_RULES_DIR).mkdir(exist_ok=True)
        rule_files = list(Path(YARA_RULES_DIR).glob("*.yar"))
        return yara.compile(filepaths={str(p): str(p) for p in rule_files}) if rule_files else None
    except Exception:
        return None

def _silent_yara_scan(file_path):
    try:
        rules = _load_yara_rules()
        return rules.match(filepath=file_path) if rules else []
    except Exception:
        return []

def analyze_file():
    try:
        # Get file path from user
        file_path = input("ENTER THE PATH OF THE FILE >> ")
        
        # Silent YARA scan (no output)
        yara_matches = _silent_yara_scan(file_path)
        
        # Original VirusTotal code below (unchanged)
        with open(file_path, "rb") as file:
            response = requests.post(
                'https://www.virustotal.com/vtapi/v2/file/scan',
                files={"file": file},
                params={"apikey": API_KEY}
            )
        
        file_url = f"https://www.virustotal.com/api/v3/files/{response.json()['sha1']}"
        headers = {"accept": "application/json", "x-apikey": API_KEY}
        
        typing_effect("ANALYSING....")
        report = requests.get(file_url, headers=headers).json()

        attributes = report["data"]["attributes"]
        name = attributes.get("meaningful_name", "N/A")
        file_hash = attributes["sha256"]
        description = attributes["type_description"]
        size_kb = attributes["size"] // 1024
        results = attributes["last_analysis_results"]

        print_bold("\nFILE INFORMATION:")
        typing_effect(f"NAME: {name}")
        typing_effect(f"SIZE: {size_kb} KB")
        typing_effect(f"DESCRIPTION: {description}")
        typing_effect(f"SHA-256 HASH: {file_hash}")
        print()

        malicious_count = 0
        print_bold("SCAN RESULTS:")
        for engine, result in results.items():
            status = result['category'].upper()
            if status == 'MALICIOUS':
                malicious_count += 1
                status = f"[MALICIOUS] {result.get('result', '')}"
            elif status == 'TYPE-UNSUPPORTED':
                status = f"[UNSUPPORTED TYPE] {result.get('result', '')}"
            else:
                status = f"[CLEAN] {result.get('result', '')}"

            typing_effect(f"{engine.upper()}: {status}")

        print()
        if malicious_count > 0:
            msg = f"WARNING: {malicious_count} ANTIVIRUS ENGINES DETECTED MALICIOUS CONTENT!"
        else:
            msg = "NO ANTIVIRUS ENGINES DETECTED MALICIOUS CONTENT!"
            
        print_bold(msg.center(80))
        print()

    except FileNotFoundError:
        typing_effect("ERROR: FILE NOT FOUND!")
    except Exception as e:
        typing_effect(f"AN ERROR OCCURRED: {str(e).upper()}")

if __name__ == "__main__":
    analyze_file()
