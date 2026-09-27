import requests
import csv
import time
import sys

# replace with your VirusTotal API key
API_KEY = "YOUR_API_KEY_HERE"
URL = "https://www.virustotal.com/api/v3/ip_addresses/"

HEADERS = {"x-apikey": API_KEY}

def check_ip(ip):
    try:
        response = requests.get(URL + ip.strip(), headers=HEADERS)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            # Returns the number of security vendors that flagged this IP as malicious
            return stats['malicious']
        else:
            return f"HTTP Error: {response.status_code}"
    except Exception as e:
        return str(e)

def main():
    print("[*] Starting Automated IP Triage...")
    
    try:
        # reads from a local text file containing one IP per line
        with open("ips.txt", "r") as file, open("triage_results.csv", "w", newline="") as out_file:
            writer = csv.writer(out_file)
            writer.writerow(["IP Address", "Malicious Flags"])
            
            for ip in file:
                ip = ip.strip()
                if not ip: 
                    continue
                
                print(f"[*] Querying VirusTotal for {ip}...")
                malicious_count = check_ip(ip)
                writer.writerow([ip, malicious_count])
                
                # free VirusTotal API limits users to 4 requests per minute
                # sleeping for 16 seconds prevents rate limit
                time.sleep(16) 

        print("[+] Triage Complete. Results exported to triage_results.csv.")
        
    except FileNotFoundError:
        print("[!] Error: 'ips.txt' not found. Please create the file and add IP addresses.")
        sys.exit(1)

if __name__ == "__main__":
    main()