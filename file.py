import yara
import requests
import json
import sys
from time import sleep
from config import API_KEY

def typing_effect(words: str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    print()

def print_bold(text: str):
    print(f"\033[1m{text}\033[0m")

def analyze_file():
    try:
        file_path = input("ENTER THE PATH OF THE FILE >> ")
        
        # Upload file to VirusTotal (v2)
        with open(file_path, "rb") as file:
            response = requests.post(
                'https://www.virustotal.com/vtapi/v2/file/scan',
                files={"file": file},
                params={"apikey": API_KEY}
            )

        file_sha1 = response.json().get("sha1")
        if not file_sha1:
            typing_effect("FAILED TO RETRIEVE SHA1 FROM VT RESPONSE.")
            return

        # Fetch v3 analysis
        file_url = f"https://www.virustotal.com/api/v3/files/{file_sha1}"
        headers = {"accept": "application/json", "x-apikey": API_KEY}
        typing_effect("ANALYSING VIA VIRUSTOTAL....")
        report = requests.get(file_url, headers=headers).json()

        # Extract basic info
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
        print_bold("VIRUSTOTAL SCAN RESULTS:")
        for engine, result in results.items():
            status = result['category'].upper()
            label = result.get('result', '')
            if status == 'MALICIOUS':
                malicious_count += 1
                typing_effect(f"{engine.upper()}: [MALICIOUS] {label}")
            elif status == 'TYPE-UNSUPPORTED':
                typing_effect(f"{engine.upper()}: [UNSUPPORTED TYPE] {label}")
            else:
                typing_effect(f"{engine.upper()}: [CLEAN] {label}")
        
        # Final verdict
        print()
        verdict = f"WARNING: {malicious_count} DETECTIONS!" if malicious_count else "FILE APPEARS CLEAN."
        print_bold(verdict.center(80))
        print()

        # === YARA SCANNING SECTION ===
        print_bold("LOCAL YARA RULES ANALYSIS:")
        try:
            # COMPILE RULES FROM FILE (EDIT PATH AS NEEDED)
            rules = yara.compile(filepath="yara_rules/suspicious_file_analysis.yar")

            # Scan file
            matches = rules.match(filepath=file_path)
            if matches:
                for match in matches:
                    typing_effect(f"[YARA MATCH] Rule: {match.rule}")
            else:
                typing_effect("No YARA rules matched this file.")
        except yara.Error as ye:
            typing_effect(f"YARA SCAN FAILED: {str(ye)}")
        except FileNotFoundError:
            typing_effect("YARA RULE FILE NOT FOUND.")

    except FileNotFoundError:
        typing_effect("ERROR: FILE NOT FOUND!")
    except Exception as e:
        typing_effect(f"AN ERROR OCCURRED: {str(e).upper()}")

if __name__ == "__main__":
    analyze_file()
