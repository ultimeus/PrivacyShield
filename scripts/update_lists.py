import requests
import os

# A list of URLs for the blocklists.
# You should get the full list from the original repo's IncludedLists.md
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://mirror1.malwaredomains.com/files/justdomains",
    "http://sysctl.org/cameleon/hosts",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    # Add all other URLs from IncludedLists.md here
]

# The name of the final output file.
OUTPUT_FILE = "PrivacyShield.txt"

# Path to a whitelist file (optional, but recommended)
WHITELIST_FILE = "whitelist.md"


def fetch_whitelist():
    """Fetches whitelisted domains from the whitelist file."""
    if not os.path.exists(WHITELIST_FILE):
        print(f"Whitelist file not found at {WHITELIST_FILE}, skipping.")
        return set()
        
    with open(WHITELIST_FILE, 'r') as f:
        # Read lines, strip whitespace, and ignore comments/empty lines
        return {line.strip() for line in f if line.strip() and not line.startswith('#')}


def process_line(line: str) -> str | None:
    """Cleans up a single line from a blocklist source."""
    # 1. Remove comments
    if '#' in line:
        line = line.split('#', 1)[0]

    # 2. Strip whitespace
    line = line.strip()

    # 3. Handle hosts file format (e.g., "0.0.0.0 example.com")
    if ' ' in line or '\t' in line:
        parts = line.split()
        if len(parts) > 1:
            line = parts[1] # Take the domain part

    # 4. Return None if the line is empty or a placeholder
    if not line or line in ['0.0.0.0', '127.0.0.1', 'localhost']:
        return None

    return line.lower() # Return the cleaned domain in lowercase


def main():
    """Main function to fetch, clean, and save the blocklist."""
    print("Starting blocklist aggregation...")
    
    # Load the whitelist
    whitelist = fetch_whitelist()
    print(f"Loaded {len(whitelist)} domains from the whitelist.")

    # Using a set for automatic deduplication
    master_list = set()

    for url in BLOCKLIST_URLS:
        try:
            print(f"Fetching: {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status() # Raise an exception for bad status codes

            for line in response.text.splitlines():
                clean_domain = process_line(line)
                if clean_domain:
                    master_list.add(clean_domain)

        except requests.RequestException as e:
            print(f"  -> Failed to fetch {url}: {e}")

    print(f"\nTotal unique domains before whitelist: {len(master_list)}")

    # Remove whitelisted domains
    final_list = sorted(list(master_list - whitelist))

    print(f"Total unique domains after whitelist: {len(final_list)}")

    # Write the final list to the output file
    with open(OUTPUT_FILE, 'w') as f:
        f.write("# PrivacyShield Blocklist\n")
        f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write(f"# Total Domains: {len(final_list)}\n")
        f.write("\n")
        for domain in final_list:
            f.write(f"{domain}\n")

    print(f"\nSuccessfully created {OUTPUT_FILE} with {len(final_list)} domains.")


if __name__ == "__main__":
    # We need to import these here so they are available in main()
    from datetime import datetime, timezone
    main()
