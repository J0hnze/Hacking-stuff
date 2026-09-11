#!/usr/bin/python3

import os
import subprocess
import requests
import json
import time

def check_and_install_tools(tools):
    for tool in tools:
        if subprocess.run(["which", tool], capture_output=True, text=True).returncode != 0:
            print(f"{tool} not found, installing...")
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "install", "-y", tool], check=True)

def fetch_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return sorted(set(entry['common_name'] for entry in data))
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"Error fetching subdomains for {domain}: {e}")
        return []

def check_subdomain_status(domain, subdomains):
    categorized_subdomains = {}
    for subdomain in subdomains:
        url = f"http://{subdomain}"
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            status_code = response.status_code
        except requests.RequestException:
            status_code = "failed"
        
        status_file = f"sites/{domain}/{status_code}-subdomains.txt"
        if status_code not in categorized_subdomains:
            categorized_subdomains[status_code] = []
        categorized_subdomains[status_code].append(subdomain)
    
    for status, subs in categorized_subdomains.items():
        with open(f"sites/{domain}/{status}-subdomains.txt", "w") as f:
            f.write("\n".join(subs) + "\n")

    return categorized_subdomains.get(200, [])

def download_robots_txt(domain, subdomains):
    for subdomain in subdomains:
        robots_url = f"http://{subdomain}/robots.txt"
        robots_file = f"sites/{domain}/robots_{subdomain}.txt"
        try:
            response = requests.get(robots_url, timeout=5)
            if response.status_code == 200:
                with open(robots_file, "w") as f:
                    f.write(response.text)
                print(f"Downloaded robots.txt from {robots_url}")
            else:
                print(f"No robots.txt found at {robots_url}")
        except requests.RequestException:
            print(f"Failed to reach {robots_url}")

def run_gowitness(domain, output_file):
    subprocess.run(["gowitness", "file", "-f", output_file, "-P", f"sites/{domain}/screenshots"], check=False)

def sleepy_time(s):
    print("Sleeping for "+(str(s))+" Seconds...")
    time.sleep(s)  # Adjust sleep time as needed to avoid rate limiting
    print("...Resuming")

def process_targets(file_path):
    if not os.path.isfile(file_path):
        print("Error: targets.txt not found!")
        return

    with open(file_path, "r") as f:
        for line in f:
            domain = line.strip()
            if not domain:
                continue

            print("=" * 25)
            print(f"Processing: {domain}")
            print("=" * 25)

            domain_dir = f"sites/{domain}"
            os.makedirs(domain_dir, exist_ok=True)
            output_file = f"{domain_dir}/subdomains.txt"

            new_subdomains = fetch_subdomains(domain)
            sleepy_time(2)
            if new_subdomains:
                valid_subdomains = check_subdomain_status(domain, new_subdomains)
                sleepy_time(2)
                if valid_subdomains:
                    output_file = f"{domain_dir}/200-subdomains.txt"
                    with open(output_file, "w") as f:
                        f.write("\n".join(valid_subdomains) + "\n")
                    print(f"Updated results in {output_file}")

                    # Check for robots.txt and download it
                    #download_robots_txt(domain, valid_subdomains)
                    sleepy_time(2)

                    # Run gowitness for screenshots
                    run_gowitness(domain, output_file)
                else:
                    print(f"No valid subdomains with status 200 found for {domain}")
            else:
                print(f"No subdomains found for {domain}")

    print("*" * 28)
    print("** All targets processed! **")
    print("*" * 28)

if __name__ == "__main__":
    check_and_install_tools(["jq", "wget", "gowitness"])
    process_targets("targets.txt")

