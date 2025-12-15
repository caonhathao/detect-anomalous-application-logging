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

from src import LogBertAnalyzer, parsing_http_requests, process_log_string

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
        e = matches[i + 1].start() if i + 1 < len(matches) else len(text)
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
    body = "\n".join(f"{i + 1}. {x}" for i, x in enumerate(batch))
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


# ================================
# UNKNOWN SCAN (NOT USED)
# ================================

INPUT_FOLDER = "./unknown"
VOCAB_SIZE = 101
ANOMALY_THRESHOLD = 0
try:
    analyzer = LogBertAnalyzer(vocab_size=VOCAB_SIZE)
except Exception as e:
    print(f"⚠️ Không thể tải LogBertAnalyzer: {e}")
    analyzer = None


def process_single_file(file_path, stats):
    if analyzer is None:
        return None

    event_ids = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            log_req = parsing_http_requests(f)
            for log_string in log_req:
                result = process_log_string(log_string)
                e_id = result.get("EventId")
                if e_id is not None:
                    event_ids.append(e_id)
    except Exception as e:
        print(f"❌ Lỗi đọc file {file_path}: {e}")
        return None

    if not event_ids:
        try:
            os.remove(file_path)
        except Exception as e:
            print(f"{file_path}: {e}")
            pass
        return None

    try:
        detection_result = analyzer.detect_anomalies(event_ids, top_k=5)
        anomaly_count = detection_result.get("anomaly_count", 0)

        is_anomalous = True if anomaly_count > ANOMALY_THRESHOLD else False

        if is_anomalous:
            stats["malicious"] += 1

            new_path = file_path + ".checked_anomaly"
            os.rename(file_path, new_path)
            print(f"🚨 [LogBERT] Anomaly Detected: {os.path.basename(file_path)}")
        else:
            os.remove(file_path)
            stats["safe"] += 1

    except Exception as e:
        print(f"❌ Lỗi khi chạy model cho {file_path}: {e}")


def unknow_scan_batch(stop_event, stats):
    if not os.path.exists(INPUT_FOLDER):
        os.makedirs(INPUT_FOLDER)

    print("🕵️  LogBERT Scanner started monitoring:", INPUT_FOLDER)
    while not stop_event.is_set():
        # Lấy danh sách file trong folder
        files = glob.glob(os.path.join(INPUT_FOLDER, "*"))

        files_to_scan = [f for f in files if not f.endswith(".checked_anomaly")]

        if not files_to_scan:
            time.sleep(2)
            continue

        for file_path in files_to_scan:
            if stop_event.is_set(): break

            process_single_file(file_path, stats)
        time.sleep(1)


# ===============================
# MAIN
# ===============================

def run():
    print("🚀 IDS LLM pipeline – FAST ONLY")

    if not os.path.exists("./unknown"):
        os.makedirs(INPUT_FOLDER)

    q = Queue(10000)
    stop = threading.Event()
    stats = {"safe": 0, "suspicious": 0, "malicious": 0}

    threading.Thread(target=log_feeder, args=(q, stop), daemon=True).start()

    threading.Thread(target=unknow_scan_batch, args=(stop, stats), daemon=True).start()

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

            if batch:
                masked = [mask(x) for x in batch]
                start = time.time()
                res = scan_batch(masked)

                for r in res:
                    stats[r] += 1
                    lat.append(time.time() - start)
                    count += 1
                    pbar.update(1)

            has_data = sum(stats.values()) > 0
            should_update = (count > 0 and count % 50 == 0) or (not batch and int(time.time()) % 2 == 0)

            if should_update:
                ax1.clear()
                if lat:
                    ax1.plot(lat[-100:])
                ax1.set_title("Latency (LLM)")

                ax2.clear()
                if has_data:
                    ax2.pie(
                        stats.values(),
                        labels=stats.keys(),
                        autopct="%1.1f%%"
                    )
                    ax2.set_title(
                        f"Total: {sum(stats.values())} | S:{stats['safe']} | M:{stats['malicious']}"
                    )
                else:
                    ax2.text(0.5, 0.5, "Waiting for data...", ha='center')

                plt.pause(0.01)

            if not batch:
                time.sleep(0.2)

    except KeyboardInterrupt:
        stop.set()
        pbar.close()

    dur = time.time() - t0
    print("\nProcessed:", count)
    print("Throughput:", count / dur, "req/s")


# ===============================
if __name__ == "__main__":
    run()
