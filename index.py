# main.py (Main Menu)
import time
import sys
from pyfiglet import figlet_format
from hash import analyze_hash
from file import analyze_file
from ip import analyze_ip
from domain import analyze_domain
from url import analyze_url

def type_effect(words: str, delay=0.02):
    for char in words:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def display_banner():
    print(figlet_format('Open Source IoC Analyzer'))
    time.sleep(1)

def main():
    display_banner()
    while True:
        print("\n=== Select an option ===")
        print("1. Hash Analysis")
        print("2. Domain Analysis")
        print("3. IP Address Analysis")
        print("4. File Upload")
        print("5. URL Analysis")
        print("6. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            try:
                hash_value = input("\nEnter hash to analyze: ").strip()
                if not hash_value:
                    type_effect("Error: No hash provided!")
                    continue
                analyze_hash(hash_value)
            except Exception as e:
                type_effect(f"Error: {str(e)}")
                
        elif choice == "2":
            try:
                domain = input("\nEnter domain to analyze: ").strip()
                if not domain:
                    type_effect("Error: No domain provided!")
                    continue
                analyze_domain(domain)
            except Exception as e:
                type_effect(f"Error: {str(e)}")
                
        elif choice == "3":
            try:
                ip = input("\nEnter IP address to analyze: ").strip()
                if not ip:
                    type_effect("Error: No IP address provided!")
                    continue
                analyze_ip(ip)
            except Exception as e:
                type_effect(f"Error: {str(e)}")
                
        elif choice == "4":
            try:
                analyze_file()
            except Exception as e:
                type_effect(f"Error: {str(e)}")
                
        elif choice == "5":
            try:
                url = input("\nEnter URL to analyze: ").strip()
                if not url:
                    type_effect("Error: No URL provided!")
                    continue
                analyze_url(url)
            except Exception as e:
                type_effect(f"Error: {str(e)}")
                
        elif choice == "6":
            type_effect("Exiting... Goodbye!")
            break
            
        else:
            type_effect("Invalid choice, please try again.")

        # Add a pause between operations
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
