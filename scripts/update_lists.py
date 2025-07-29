import requests
import os
import re
from datetime import datetime, timezone

# --- CONFIGURATION ---

# The file containing the source lists (both blocklists and whitelists).
SOURCE_LISTS_FILE = "IncludedLists.md"

# The local whitelist file for manual overrides and false positives.
LOCAL_WHITELIST_FILE = "whitelist.md"

# The final output file for the aggregated blocklist.
OUTPUT_FILE = "PrivacyShield.txt"


def parse_source_lists(file_path: str) -> tuple[list, list]:
    """
    Parses the Markdown file to extract blocklist and whitelist URLs.
    
    Args:
        file_path: The path to the Markdown file (e.g., "IncludedLists.md").

    Returns:
        A tuple containing two lists: (blocklist_urls, whitelist_urls).
    """
    blocklist_urls = []
    whitelist_urls = []
    current_section = None
    # Regex to find a URL within Markdown link syntax, e.g., [Name](http://a.com)
    url_pattern = re.compile(r'\((https?://[^\)]+)\)')

    print(f"Reading source lists from: {file_path}")
    with open(file_path, 'r') as f:
        for line in f:
            # Determine which section we are in
            if "## Block Lists" in line:
                current_section = "block"
                continue
            if "## White List" in line:
                current_section = "white"
                continue

            # If we are in a section, look for list items with URLs
            if current_section and line.strip().startswith('-'):
                match = url_pattern.search(line)
                if match:
                    url = match.group(1)
                    if current_section == "block":
                        blocklist_urls.append(url)
                    elif current_section == "white":
                        whitelist_urls.append(url)
                        
    print(f"Found {len(blocklist_urls)} blocklist sources.")
    print(f"Found {len(whitelist_urls)} whitelist sources.")
    return blocklist_urls, whitelist_urls


def process_line(line: str) -> str | None:
    """Cleans up a single line from a blocklist or whitelist source."""
    # 1. Remove comments
    if '#' in line:
        line = line.split('#', 1)[0]

    # 2. Strip whitespace
    line = line.strip()

    # 3. Handle hosts file format (e.g., "0.0.0.0 example.com")
    if ' ' in line or '\t' in line:
        parts = line.split()
        if len(parts) > 1 and not parts[0].startswith('#'):
            line = parts[1]

    # 4. Return None if the line is empty or a placeholder address
    if not line or line in ['0.0.0.0', '127.0.0.1', 'localhost', '::1']:
        return None

    # 5. Convert to lowercase for consistency
    return line.lower()


def fetch_domains_from_urls(urls: list[str]) -> set[str]:
    """
    Fetches content from a list of URLs and returns a set of processed domains.
    """
    domain_set = set()
    for url in urls:
        try:
            print(f"  Fetching: {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()  # Raise an HTTPError for bad responses

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
    with open(file_path, 'r') as f:
        for line in f:
            clean_domain = process_line(line)
            if clean_domain:
                whitelisted_domains.add(clean_domain)
    print(f"Loaded {len(whitelisted_domains)} domains from local whitelist '{file_path}'.")
    return whitelisted_domains


def main():
    """Main function to run the entire update process."""
    print("--- Starting Blocklist Update Process ---")
    
    # Step 1: Get the source URLs from the Markdown file
    blocklist_urls, whitelist_urls = parse_source_lists(SOURCE_LISTS_FILE)

    # Step 2: Fetch all domains from the blocklist URLs
    print("\n--- Fetching Blocklists ---")
    blocked_domains = fetch_domains_from_urls(blocklist_urls)
    print(f"\nTotal unique domains from blocklists: {len(blocked_domains)}")

    # Step 3: Fetch all domains from whitelist URLs and the local whitelist file
    print("\n--- Fetching Whitelists ---")
    remote_whitelist = fetch_domains_from_urls(whitelist_urls)
    local_whitelist = get_local_whitelist(LOCAL_WHITELIST_FILE)
    
    # Combine both whitelists into one final set
    final_whitelist = remote_whitelist.union(local_whitelist)
    print(f"\nTotal unique domains in combined whitelist: {len(final_whitelist)}")

    # Step 4: Filter the blocked domains against the final whitelist
    final_blocklist = sorted(list(blocked_domains - final_whitelist))
    print(f"Total domains after applying whitelist: {len(final_blocklist)}")

    # Step 5: Write the final, clean list to the output file
    print(f"\nWriting {len(final_blocklist)} domains to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w') as f:
        f.write("# PrivacyShield Blocklist\n")
        f.write(f"# Generated by GitHub Actions on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write(f"# Total Domains: {len(final_blocklist)}\n")
        f.write("#\n")
        for domain in final_blocklist:
            f.write(f"{domain}\n")

    print("\n--- Process Complete ---")


if __name__ == "__main__":
    main()
