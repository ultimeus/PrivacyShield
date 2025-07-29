import requests
import os
import re
from datetime import datetime, timezone

# --- CONFIGURATION ---
SOURCE_LISTS_FILE = "IncludedLists.md"
LOCAL_WHITELIST_FILE = "whitelist.md"
OUTPUT_FILE = "PrivacyShield.txt"


def parse_source_lists(file_path: str) -> tuple[list[str], list[str]]:
    """
    Parses the Markdown file to extract blocklist and whitelist URLs.
    This version is adapted for formats with headings and bare URLs on new lines.
    """
    blocklist_urls, whitelist_urls = [], []
    current_section = None
    
    print(f"Reading source lists from: {file_path}")
    if not os.path.exists(file_path):
        print(f"  -> FATAL: Source file '{file_path}' not found!")
        return [], []

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            clean_line = line.strip().lower()

            # --- Section Header Detection ---
            # Looks for headings that contain "block list" or "white list".
            if clean_line.startswith('##') and 'block list' in clean_line:
                current_section = "block"
                print("--> Found Block Lists section")
                continue
            if clean_line.startswith('##') and 'white list' in clean_line:
                current_section = "white"
                print("--> Found White List section")
                continue
            
            # --- URL Extraction ---
            # If we are inside a section, check if the entire line is a URL.
            if current_section:
                if clean_line.startswith('http://') or clean_line.startswith('https://'):
                    url = line.strip() # Use the original line with correct case
                    print(f"    - Extracted URL: {url}")
                    if current_section == "block":
                        blocklist_urls.append(url)
                    elif current_section == "white":
                        whitelist_urls.append(url)
                        
    print(f"\nFound {len(blocklist_urls)} blocklist sources.")
    print(f"Found {len(whitelist_urls)} whitelist sources.")
    return blocklist_urls, whitelist_urls


def process_line(line: str) -> str | None:
    """Cleans up a single line from a blocklist or whitelist source."""
    if '#' in line:
        line = line.split('#', 1)[0]
    line = line.strip()
    if ' ' in line or '\t' in line:
        parts = line.split()
        if len(parts) > 1 and not parts[0].startswith('#'):
            line = parts[1]
    if not line or line in ['0.0.0.0', '127.0.0.1', 'localhost', '::1']:
        return None
    return line.lower()

def fetch_domains_from_urls(urls: list[str]) -> set[str]:
    """Fetches content from a list of URLs and returns a set of processed domains."""
    domain_set = set()
    for url in urls:
        try:
            print(f"  Fetching: {url}")
            # Add a user-agent to mimic a browser, as some servers block scripts.
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
            response = requests.get(url, timeout=45, headers=headers)
            response.raise_for_status()
            for line in response.text.splitlines():
                clean_domain = process_line(line)
                if clean_domain:
                    domain_set.add(clean_domain)
        except requests.RequestException as e:
            print(f"    -> WARNING: Failed to fetch {url}. Reason: {e}")
    return domain_set

def get_local_whitelist(file_path: str) -> set[str]:
    """Fetches whitelisted domains from a local file."""
    if not os.path.exists(file_path):
        print(f"Local whitelist not found at '{file_path}', skipping.")
        return set()
    whitelisted_domains = set()
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            clean_domain = process_line(line)
            if clean_domain:
                whitelisted_domains.add(clean_domain)
    print(f"Loaded {len(whitelisted_domains)} domains from local whitelist '{file_path}'.")
    return whitelisted_domains

def main():
    """Main function to run the entire update process."""
    print("--- Starting Blocklist Update Process ---")
    
    blocklist_urls, whitelist_urls = parse_source_lists(SOURCE_LISTS_FILE)
    if not blocklist_urls:
        print("\nFATAL: No blocklist URLs were found. Exiting to prevent creating an empty file.")
        return

    print("\n--- Fetching Blocklists ---")
    blocked_domains = fetch_domains_from_urls(blocklist_urls)
    print(f"\nTotal unique domains from blocklists: {len(blocked_domains)}")

    print("\n--- Fetching Whitelists ---")
    remote_whitelist = fetch_domains_from_urls(whitelist_urls)
    local_whitelist = get_local_whitelist(LOCAL_WHITELIST_FILE)
    
    final_whitelist = remote_whitelist.union(local_whitelist)
    print(f"\nTotal unique domains in combined whitelist: {len(final_whitelist)}")

    final_blocklist = sorted(list(blocked_domains - final_whitelist))
    print(f"Total domains after applying whitelist: {len(final_blocklist)}")

    print(f"\nWriting {len(final_blocklist)} domains to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("# PrivacyShield Blocklist\n")
        f.write(f"# Generated by GitHub Actions on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write(f"# Total Domains: {len(final_blocklist)}\n")
        f.write("#\n")
        for domain in final_blocklist:
            f.write(f"{domain}\n")

    print("\n--- Process Complete ---")

if __name__ == "__main__":
    main()
