import shutil
import os, time, random, json
from pathlib import Path
import requests
import threading
import asyncio
import websockets
from queue import Queue
from dotenv import load_dotenv
load_dotenv()

# ==========================
# CONFIG
# ==========================
SERVICES = [
    "http://localhost:5001/api/v1/generate",
    "http://localhost:5002/api/v1/generate",
]

LOG_FOLDER = os.getenv("LOG_FOLDER")
if not LOG_FOLDER or not os.path.exists(LOG_FOLDER):
    raise Exception(f"LOG_FOLDER '{LOG_FOLDER}' does not exist!")

MISSED_DIR = "logs_missed"
os.makedirs(MISSED_DIR, exist_ok=True)

FN_PATH = os.path.join(MISSED_DIR, "false_negative.txt")
FP_PATH = os.path.join(MISSED_DIR, "false_positive.txt")
UNK_PATH = os.path.join(MISSED_DIR, "unknown.txt")


DEBUG_FOLDER = "debug_logs"
UPDATE_CHART_EVERY = 200
WORKER_COUNT = 4          # số worker xử lý song song
REQUEST_TIMEOUT = 8       # timeout khi gọi service

SYSTEM_START = time.time()

throughput_stats = {
    "tokens": 0,        # tổng số token output
    "requests": 0       # tổng request đã xử lý
}

# ==========================
# GLOBAL STATS
# ==========================
stats = {
    "total": 0,
    "safe": 0,
    "malicious": 0,
    "unknown": 0,
    "latencies": [],
}

eval_stats = {
    "TP": 0,
    "TN": 0,
    "FP": 0,
    "FN": 0
}

ws_clients = set()
ws_loop = None


def log_missed(path, gt, pred, req_text):
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[GT={gt} | PRED={pred}]\n{req_text}\n\n")


# ==========================
# SERVICE HEALTH
# ==========================
service_status = {s: True for s in SERVICES}
RR = 0

def route_smart():
    """Round-robin thông minh: bỏ qua service đang lỗi."""
    global RR
    for _ in range(len(SERVICES)):
        RR = (RR + 1) % len(SERVICES)
        srv = SERVICES[RR]
        if service_status.get(srv, True):
            return srv
    return SERVICES[0]  # fallback cuối

# ==========================
# HEALTH CHECK (auto recover)
# ==========================
def healthcheck():
    while True:
        for srv in SERVICES:
            try:
                # health = GET /
                url = srv.replace("/api/v1/generate", "/")
                requests.get(url, timeout=2)
                service_status[srv] = True
            except:
                service_status[srv] = False
        time.sleep(5)

# ==========================
# MASKING NÂNG CAO
# ==========================
import re, urllib.parse, base64

def safe_b64_decode(s):
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except:
        return s

def selective_mask(text):
    text = text.replace("\r", "").replace("\t", " ")
    decoded = urllib.parse.unquote(text)

    decoded = re.sub(r'\b\d{1,3}(\.\d{1,3}){3}\b', '<IP>', decoded)
    decoded = re.sub(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '<UUID>', decoded)
    decoded = re.sub(r'(token|sessionid|jwt|auth)=([A-Za-z0-9\-_]{20,})', r'\1=<TOKEN>', decoded, flags=re.IGNORECASE)
    decoded = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', '<TIME>', decoded)

    return decoded

# ==========================
# RISK SCORING NÂNG CAO
# ==========================
def risk_score_advanced(text):
    """
    Risk scoring nâng cao: rule-based detection.
    Trả về số điểm nguy cơ dựa trên SQLi, XSS, RCE, traversal, scanning.
    """

    score = 0
    low = text.lower()

    # ===== SQL Injection =====
    sql_patterns = [
        ("' or '1'='1", 8),
        (" or 1=1", 6),
        ("union select", 10),
        ("--", 4),
        ("sleep(", 6),
        ("@@version", 4),
        ("information_schema", 6),
        ("'||", 3),
        ("'%20or%20", 6),
    ]
    for pat, w in sql_patterns:
        if pat in low:
            score += w

    # ===== XSS =====
    xss_patterns = [
        ("<script", 10),
        ("javascript:", 6),
        ("onerror=", 6),
        ("onload=", 5),
        ("<img", 3),
        ("svg/on", 6),
    ]
    for pat, w in xss_patterns:
        if pat in low:
            score += w

    # ===== PATH TRAVERSAL =====
    traversal_patterns = [
        ("../", 8),
        ("%2e%2e%2f", 8),
        ("%2e%2e/", 7),
        ("/etc/passwd", 10),
        ("c:\\windows", 7),
    ]
    for pat, w in traversal_patterns:
        if pat in low:
            score += w

    # ===== COMMAND INJECTION =====
    cmd_patterns = [
        (";ls", 8),
        ("| ls", 8),
        ("| id", 8),
        ("| whoami", 8),
        ("wget http", 6),
        ("curl http", 6),
        ("$(id)", 10),
        ("||", 4),
    ]
    for pat, w in cmd_patterns:
        if pat in low:
            score += w

    # ===== SCANNING / BRUTEFORCE =====
    brute_patterns = [
        ("/phpmyadmin", 5),
        ("/wp-admin", 5),
        ("admin", 1),
        ("login", 1),
    ]

    ssi_patterns = [
    ("<!--#exec", 10),
    ("<!--#include", 10),
    ("<!--#", 6),
    ]

    for pat, w in ssi_patterns:
        if pat in low:
            score += w

    html_inject_patterns = [
        ("\"><", 8),
        ("</script>", 8),
        ("<script", 8),
    ]

    for pat, w in html_inject_patterns:
        if pat in low:
            score += w

    encoded_traversal = [
        ("%2e%2e%2f", 10),
        ("%2e%2e/", 10),
        ("%2e/", 8),
    ]

    for pat, w in encoded_traversal:
        if pat in low:
            score += w

    faulty_body_patterns = [
        ("precio=", 1),
        ("B1=", 1),
    ]

    for pat, w in faulty_body_patterns:
        if pat in low:
            score += w

    for pat, w in brute_patterns:
        if pat in low:
            score += w

    # ===== RARE HTTP METHODS =====
    if low.startswith(("trace", "connect", "debug")):
        score += 10

    return score

# ==========================
# PARSE LABELED REQUEST
# ==========================
def extract_label_from_line(block):
    lines = block.splitlines()
    label_line = lines[0].strip()
    label = label_line.replace("|", "").lower()
    req_text = "\n".join(lines[1:])
    return label, req_text


# ==========================
# SMART SEND REQUEST (Retry + Skip + Auto-mark unhealthy)
# ==========================
def send_request(prompt, retries=2):
    payload = {
        "prompt": prompt,
        "temperature": 0.0,
        "top_p": 1.0,
        "max_length": 32
    }

    for _ in range(retries):
        srv = route_smart()
        try:
            start = time.time()
            resp = requests.post(srv, json=payload, timeout=REQUEST_TIMEOUT)
            latency = time.time() - start

            if resp.status_code == 200:
                text = resp.json()["results"][0]["text"].strip()
                # Estimate token count (approx)
                token_est = len(text.split())
                throughput_stats["tokens"] += token_est
                throughput_stats["requests"] += 1

                clean = text.strip().lower()
                print("LLM RAW OUTPUT:", repr(text))
                    # Accept direct output
                if clean in ("safe", "malicious", "unknown"):
                    return clean, latency

        except:
            service_status[srv] = False

    return None, 0

# ==========================
# PROMPT BUILDERS
# ==========================
def build_prompt_simple(masked, allow_unknown=True):
    if allow_unknown:
        choices = "safe\nmalicious\nunknown"
    else:
        choices = "safe\nmalicious"

    return (
        "Classify the HTTP request.\n"
        "Answer with one of the following words exactly:\n"
        "safe\nmalicious\nunknown\n\n"
        f"Request:\n{masked}\n\n"
        "Answer:"
    )


# ==========================
# LLM ANALYSIS PIPELINE
# ==========================
def analyze_log(req_text):
    masked = selective_mask(req_text)

    # ------------------------------------
    # LEVEL 1 — cho phép unknown
    # ------------------------------------
    p1 = build_prompt_simple(masked, allow_unknown=True)
    label, lat = send_request(p1)

    if label in ("safe", "malicious", "unknown"):
        return label, lat

    # ------------------------------------
    # LEVEL 2 — không cho phép unknown
    # ------------------------------------
    p2 = build_prompt_simple(masked, allow_unknown=False)
    label2, lat2 = send_request(p2)

    if label2 in ("safe", "malicious"):
        return label2, lat2

    # ------------------------------------
    # LEVEL 3 — deep fallback (same style)
    # ------------------------------------
    p3 = (
        "Classify the HTTP request.\n"
        "Possible answers:\n"
        "safe\nmalicious\n\n"
        "Rules:\n"
        "- Output EXACTLY one word.\n"
        "- No explanation.\n\n"
        f"Request:\n{masked}\n\n"
        "Answer:"
    )

    deep, dlat = send_request(p3)

    if deep in ("safe", "malicious"):
        return deep, dlat

    # ------------------------------------
    # STILL UNKNOWN → coi là unknown
    # ------------------------------------
    return "unknown", lat



# ==========================
# SPLIT requests from file
# ==========================
def split_requests_rfc(content):
    """
    Tách request theo block:
    SAFE|
    POST ...
    Headers
    ...
    (rỗng)
    MALICIOUS|
    GET ...
    Headers
    """
    reqs = []
    current = []

    lines = content.splitlines()

    for line in lines:
        # Nếu là dòng NHÃN → bắt đầu request mới
        if line.strip() in ("SAFE|", "MALICIOUS|"):
            # Nếu block cũ tồn tại → thêm vào list
            if current:
                reqs.append("\n".join(current).strip())
                current = []
        
        current.append(line)

    # Block cuối
    if current:
        reqs.append("\n".join(current).strip())

    return reqs


# ==========================
# WORKER THREAD
# ==========================
job_queue = Queue()
incident_queue = Queue()

def worker():
    while True:
        job = job_queue.get()
        src_file=job["file"]
        src_path=job["path"]
        raw_line = job["request"]

        try:
            # gt: ground truth label. pred: predicted label
            gt, req_text = extract_label_from_line(raw_line)
            risk = risk_score_advanced(req_text)

            HIGH, LOW = 12, 1
            # If rish is very high, so we mark it as malicious directly and send incident alert
            if risk >= HIGH:
                pred = "malicious"
                latency = 0
                incident_queue.put({
                    "type": pred,
                    "file": src_file,
                    "path": src_path,
                    "request": req_text,
                    "timestamp": time.time()
                })
            else:
                pred, latency = analyze_log(req_text)

            # --- LOG UNKNOWN ---
            # If the resutl is UNKNOWN, so we send incident alert and write to log about the case
            if pred == "unknown":
                log_missed(UNK_PATH, gt, pred, req_text)
                incident_queue.put({
                    "type": pred,
                    "file": src_file,
                    "path": src_path,
                    "request": req_text,
                    "timestamp": time.time()
                })

            # --- LOG FALSE NEGATIVE (VERY DANGER) ---
            # If the resutl is malicious, so we send incident alert and write to log about the case
            if gt == "malicious" and pred == "safe":
                log_missed(FN_PATH, gt, pred, req_text)

            # --- LOG FALSE POSITIVE ---
            if gt == "safe" and pred == "malicious":
                log_missed(FP_PATH, gt, pred, req_text)
                incident_queue.put({
                    "type": pred,
                    "file": src_file,
                    "path": src_path,
                    "request": req_text,
                    "timestamp": time.time()
                })


            # Update confusion matrix
            if gt == "malicious":
                if pred == "malicious": eval_stats["TP"] += 1
                else: eval_stats["FN"] += 1
                incident_queue.put({
                    "type": pred,
                    "file": src_file,
                    "path": src_path,
                    "request": req_text,
                    "timestamp": time.time()
                })

            elif gt == "safe":
                if pred == "safe": eval_stats["TN"] += 1
                else: eval_stats["FP"] += 1

            # Update stats
            stats["total"] += 1
            stats["latencies"].append(latency if latency is not None else 0)
            stats[pred] += 1

            if stats["total"] % UPDATE_CHART_EVERY == 0:
                push_stats_safe()

        except Exception as e:
            print("Worker error:", e)

        job_queue.task_done()


# Spawn workers
for _ in range(WORKER_COUNT):
    threading.Thread(target=worker, daemon=True).start()
    
# ==========================
# INCIDENT HANDLER
# ==========================
def incident_handler():
    os.makedirs("malicious", exist_ok=True)
    os.makedirs("unknown", exist_ok=True)

    while True:
        inc = incident_queue.get()

        tag = inc["type"]
        src = inc["path"]

        # Log request + filename
        incident_lock = threading.Lock()
        with incident_lock:
            with open(f"{tag}_requests.txt", "a", encoding="utf-8") as f:
                f.write(
                    f"[{time.ctime(inc['timestamp'])}] "
                    f"FILE={inc['file']}\n"
                    f"{inc['request']}\n\n"
                )

        # Copy source file (one time only)
        dst = os.path.join(tag, os.path.basename(src))
        if not os.path.exists(dst):
            shutil.copy2(src, dst)

        incident_queue.task_done()
threading.Thread(target=incident_handler, daemon=True).start()


# ==========================
# METRIC CALCULATION
# ==========================
def calc_metrics():
    TP = eval_stats["TP"]
    FP = eval_stats["FP"]
    TN = eval_stats["TN"]
    FN = eval_stats["FN"]

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall    = TP / (TP + FN) if (TP + FN) else 0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    return precision, recall, f1

def calc_throughput():
    elapsed = time.time() - SYSTEM_START

    rps = throughput_stats["requests"] / elapsed if elapsed > 0 else 0
    tps = throughput_stats["tokens"] / elapsed if elapsed > 0 else 0

    return rps, tps


# ==========================
# WEBSOCKET
# ==========================
async def push_stats():
    precision, recall, f1 = calc_metrics()
    rps, tps = calc_throughput()
    lat_vals = [x for x in stats["latencies"] if isinstance(x, (int, float))]
    avg_lat = sum(lat_vals) / len(lat_vals) if lat_vals else 0


    msg = json.dumps({
        "total": stats["total"],
        "safe": stats["safe"],
        "malicious": stats["malicious"],
        "unknown": stats["unknown"],
        "TP": eval_stats["TP"],
        "TN": eval_stats["TN"],
        "FP": eval_stats["FP"],
        "FN": eval_stats["FN"],
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "rps": rps,
        "tps": tps,
        "avg_latency": avg_lat
    })

    dead = []
    for ws in ws_clients:
        try:
            await ws.send(msg)
        except:
            dead.append(ws)

    for ws in dead:
        ws_clients.remove(ws)


def push_stats_safe():
    if ws_loop:
        asyncio.run_coroutine_threadsafe(push_stats(), ws_loop)

def stats_pusher():
    while True:
        push_stats_safe()
        time.sleep(1)   # gửi mỗi giây

threading.Thread(target=stats_pusher, daemon=True).start()

# ==========================
# MAIN SIMULATION
# ==========================

# Load logs and enqueue requests
# We will simulate the speed at which log files are generated in real time.
def start_simulation():
    files = sorted(Path(LOG_FOLDER).glob("*.txt"))

    for file in files:
        content = file.read_text(errors="ignore")
        reqs = split_requests_rfc(content)

        for req in reqs:
            # We will take some infomation when scanning any request from the log file.
            job_queue.put({
                "file":file.name,
                "path":str(file),
                "request": req
            })

        time.sleep(random.uniform(0.05, 0.2))


# ==========================
# WEBSOCKET SERVER
# ==========================
async def ws_handler(websocket):
    ws_clients.add(websocket)
    try:
        async for _ in websocket:
            pass
    finally:
        ws_clients.remove(websocket)


async def websocket_main():
    async with websockets.serve(ws_handler, "0.0.0.0", 8765):
        print("WebSocket server started on ws://0.0.0.0:8765")
        await asyncio.Future()


def start_websocket_server():
    global ws_loop
    ws_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(ws_loop)
    ws_loop.run_until_complete(websocket_main())
    ws_loop.run_forever()


# ==========================
# ENTRY
# ==========================
async def main_async():

    # Start websocket server
    server = websockets.serve(ws_handler, "0.0.0.0", 8765)
    await server
    print("WebSocket server started on ws://0.0.0.0:8765")

    # Start periodic stats pusher
    async def async_stats_pusher():
        while True:
            await push_stats()
            await asyncio.sleep(1)

    asyncio.create_task(async_stats_pusher())

    # Run simulation in background thread (non-blocking)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, start_simulation)

if __name__ == "__main__":
    asyncio.run(main_async())
