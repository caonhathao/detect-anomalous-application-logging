import os
import re
import glob
import time
import threading
from queue import Queue, Empty

import matplotlib.pyplot as plt
from tqdm import tqdm
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# ===============================
# CONFIG
# ===============================

LOG_FOLDER = os.getenv("LOG_FOLDER", "./logs")
API_URLS = [
    "http://localhost:5001/v1",
    "http://localhost:5002/v1",
]

MODEL_NAME = "koboldcpp"
BATCH_SIZE = 2
SCAN_INTERVAL = 0.5
MAX_RETRIES = 2
TIMEOUT = 8

# ===============================
# CLIENT POOL
# ===============================

clients = [OpenAI(base_url=u, api_key="sk-none") for u in API_URLS]
_rr = 0
_lock = threading.Lock()

def get_client():
    global _rr
    with _lock:
        c = clients[_rr]
        _rr = (_rr + 1) % len(clients)
    return c

# ===============================
# PARSER
# ===============================

METHOD_RE = re.compile(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s', re.MULTILINE)

def parse_requests(text):
    matches = list(METHOD_RE.finditer(text))
    reqs = []
    for i in range(len(matches)):
        s = matches[i].start()
        e = matches[i+1].start() if i+1 < len(matches) else len(text)
        chunk = text[s:e].strip()
        if len(chunk) > 20:
            reqs.append(chunk)
    return reqs

# ===============================
# MASKING
# ===============================

def mask(text):
    text = re.sub(r'\b\d{1,3}(\.\d{1,3}){3}\b', '<IP>', text)
    text = re.sub(r'[a-f0-9]{32,}', '<HASH>', text)
    text = re.sub(r'\b\d{6,}\b', '<NUM>', text)
    text = re.sub(r'http://[\w\.-]+(:\d+)?', 'http://<HOST>', text)
    return text.strip()

# ===============================
# PROMPT
# ===============================

def build_prompt(batch):
    body = "\n".join(f"{i+1}. {x}" for i, x in enumerate(batch))
    return f"""
You are an intrusion detection system.

Classify each HTTP request.

Rules:
- Malicious ONLY if clear attack intent.
- Safe if normal traffic.
- Suspicious if uncertain.
- DO NOT guess.

{body}

Answer in order using ONLY:
Safe
Suspicious
Malicious
""".strip()

# ===============================
# FAST SCAN ONLY
# ===============================

def scan_batch(masked_logs):
    prompt = build_prompt(masked_logs)

    for _ in range(MAX_RETRIES):
        try:
            res = get_client().completions.create(
                model=MODEL_NAME,
                prompt=prompt,
                temperature=0,
                max_tokens=32,
                timeout=TIMEOUT
            )
            lines = res.choices[0].text.splitlines()
            out = []
            for i in range(len(masked_logs)):
                t = lines[i].lower() if i < len(lines) else ""
                if "malicious" in t:
                    out.append("malicious")
                elif "safe" in t:
                    out.append("safe")
                else:
                    out.append("suspicious")
            return out
        except:
            time.sleep(0.3)

    return ["suspicious"] * len(masked_logs)

# ===============================
# FEEDER
# ===============================

def log_feeder(q, stop):
    offsets = {}
    print("📡 Log feeder started")

    while not stop.is_set():
        for fp in glob.glob(f"{LOG_FOLDER}/*.log") + glob.glob(f"{LOG_FOLDER}/*.txt"):
            try:
                size = os.path.getsize(fp)
                last = offsets.get(fp, 0)
                if size <= last:
                    continue

                with open(fp, "r", errors="ignore") as f:
                    f.seek(last)
                    data = f.read()
                    offsets[fp] = size

                for r in parse_requests(data):
                    q.put(r, timeout=1)
            except:
                pass

        time.sleep(SCAN_INTERVAL)

# ===============================
# MAIN
# ===============================

def run():
    print("🚀 IDS LLM pipeline – FAST ONLY")

    q = Queue(10000)
    stop = threading.Event()
    threading.Thread(target=log_feeder, args=(q, stop), daemon=True).start()

    stats = {"safe": 0, "suspicious": 0, "malicious": 0}
    lat = []
    count = 0
    t0 = time.time()

    plt.ion()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    pbar = tqdm(unit="req")

    try:
        while True:
            batch = []
            while len(batch) < BATCH_SIZE:
                try:
                    batch.append(q.get(timeout=0.5))
                except Empty:
                    break

            if not batch:
                time.sleep(0.2)
                continue

            masked = [mask(x) for x in batch]
            start = time.time()
            res = scan_batch(masked)

            for r in res:
                stats[r] += 1
                lat.append(time.time() - start)
                count += 1
                pbar.update(1)

            if count % 50 == 0:
                ax1.clear()
                ax1.plot(lat[-100:])
                ax1.set_title("Latency")

                ax2.clear()
                ax2.pie(
                    stats.values(),
                    labels=stats.keys(),
                    autopct="%1.1f%%"
                )
                ax2.set_title(
                    f"S:{stats['safe']} | Su:{stats['suspicious']} | M:{stats['malicious']}"
                )
                plt.pause(0.01)

    except KeyboardInterrupt:
        stop.set()
        pbar.close()

    dur = time.time() - t0
    print("\nProcessed:", count)
    print("Throughput:", count / dur, "req/s")

# ===============================
if __name__ == "__main__":
    run()
