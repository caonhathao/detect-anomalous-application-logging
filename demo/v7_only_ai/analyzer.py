import shutil
import os, time, random, json
from pathlib import Path
import requests
import threading
import asyncio
import websockets
from queue import Queue
from dotenv import load_dotenv
import glob
from collections import deque
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src import LogBertAnalyzer, parsing_http_requests, process_log_string, LlmExplainer

gemini_explainer = LlmExplainer()

# ==== LOG DIRECTORIES (luôn tính từ ROOT) ====
BASE_LOG_DIR = os.path.join(ROOT_DIR, "logs")
os.makedirs(BASE_LOG_DIR, exist_ok=True)

# Folder chứa các file bị miss (FN, FP, unknown case)
MISSED_DIR = os.path.join(BASE_LOG_DIR, "logs_missed")

os.makedirs(MISSED_DIR, exist_ok=True)

FN_PATH = os.path.join(MISSED_DIR, "false_negative.txt")
FP_PATH = os.path.join(MISSED_DIR, "false_positive.txt")
UNK_PATH = os.path.join(MISSED_DIR, "unknown.txt")

DEBUG_FOLDER = os.path.join(BASE_LOG_DIR, "debug_logs")
os.makedirs(DEBUG_FOLDER, exist_ok=True)



load_dotenv()

# ==========================
# SERVICE LIST
# ==========================
SERVICES = [
    "http://localhost:5001/api/v1/generate",
    "http://localhost:5002/api/v1/generate",
]

# ==========================
# SERVICE CONCURRENCY CONTROL
# ==========================
SERVICE_CONCURRENCY = 2  # mỗi service tối đa 2 request đồng thời

service_semaphores = {srv: threading.Semaphore(SERVICE_CONCURRENCY) for srv in SERVICES}

# ==========================
# CONFIG
# ==========================
LOG_FOLDER = os.getenv("LOG_FOLDER")
if not LOG_FOLDER or not os.path.exists(LOG_FOLDER):
    raise Exception(f"LOG_FOLDER '{LOG_FOLDER}' does not exist!")

UNKNOWN_FOLDER = os.path.join(BASE_LOG_DIR, "unknown")
MALICIOUS_FOLDER = os.path.join(BASE_LOG_DIR, "malicious")
SAFE_FOLDER = os.path.join(BASE_LOG_DIR, "safe")

# create new
os.makedirs(UNKNOWN_FOLDER, exist_ok=True)
os.makedirs(MALICIOUS_FOLDER, exist_ok=True)
os.makedirs(SAFE_FOLDER, exist_ok=True)


UPDATE_CHART_EVERY = 100
WORKER_COUNT = 4  # số worker xử lý song song
REQUEST_TIMEOUT = 8  # timeout khi gọi service

throughput_stats = {
    "tokens": 0,  # tổng số token output
    "requests": 0,  # tổng request đã xử lý
}

# ==========================
# GLOBAL STATS
# ==========================
stats_l1 = {
    "total": 0,
    "safe": 0,
    "malicious": 0,
    "unknown": 0,
    "latencies": [],
}
stats_l2 = {
    "total": 0,
    "safe": 0,
    "malicious": 0,
    "latencies": [],
}
# using for LlaMA request-level debug
eval_stats_l1 = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

# using for LogBERT file-level debug
eval_stats_l2 = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

file_gt = {}
file_pred = {}
file_state = (
    {}
)  # {filename: {"has_mal": False, "has_unknown": False, "first_seen": True}}

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

    decoded = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<IP>", decoded)
    decoded = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "<UUID>",
        decoded,
    )
    decoded = re.sub(
        r"(token|sessionid|jwt|auth)=([A-Za-z0-9\-_]{20,})",
        r"\1=<TOKEN>",
        decoded,
        flags=re.IGNORECASE,
    )
    decoded = re.sub(r"\b\d{2}:\d{2}:\d{2}\b", "<TIME>", decoded)

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
        ('"><', 8),
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

    if ".jsp/" in low:
        score += 5
    
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
    payload = {"prompt": prompt, "temperature": 0.0, "top_p": 1.0, "max_length": 32}

    for _ in range(retries):
        srv = route_smart()
        sem = service_semaphores[srv]
        # if service is busy, skip to next
        acquired = sem.acquire(timeout=REQUEST_TIMEOUT)
        if not acquired:
            continue
        try:
            start = time.time()
            resp = requests.post(srv, json=payload, timeout=REQUEST_TIMEOUT)
            latency = time.time() - start

            if resp.status_code == 200:
                text = resp.json()["results"][0]["text"].strip()
                # Estimate token count (approx)
                token_est = len(text.split())
                throughput_stats["tokens"] += token_est
                # print('Token used:', token_est)
                throughput_stats["requests"] += 1

                clean = text.strip().lower()
                print(f"[LLM {srv}] RAW:", repr(text))

                # Accept direct output
                if clean in ("safe", "malicious", "unknown"):
                    return clean, latency

        except Exception as e:
            print(f"[ERROR] {srv}:{e}")
            service_status[srv] = False
        finally:
            sem.release()

    return None, 0


# ==========================
# PROMPT BUILDERS
# ==========================
def build_prompt_simple(masked):
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

    p1 = build_prompt_simple(masked)
    label, lat = send_request(p1)

    if label not in ("safe", "malicious", "unknown"):
        label = "unknown"
    return label, lat


# ==========================
# SPLIT requests from file
# ==========================
def split_requests_rfc(content, filename):
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

    is_malicious = False

    for line in lines:
        # Nếu là dòng NHÃN → bắt đầu request mới
        if line.strip() in ("SAFE|", "MALICIOUS|"):
            if line.strip() == "MALICIOUS|":
                is_malicious = True
            # Nếu block cũ tồn tại → thêm vào list
            if current:
                reqs.append("\n".join(current).strip())
                current = []

        current.append(line)

    # Block cuối
    if current:
        reqs.append("\n".join(current).strip())

    file_gt[filename] = "malicious" if is_malicious else "safe"
    return reqs


# ==========================
# WORKER THREAD
# ==========================
job_queue = Queue(maxsize=500)
incident_queue = Queue()


def worker():
    while True:
        job = job_queue.get()
        src_file = job["file"]
        src_path = job["path"]
        raw_line = job["request"]
        current_idx = job["index"]
        all_req = job["all_request"]

        try:
            # Khởi tạo state nếu chưa có
            if src_file not in file_state:
                file_state[src_file] = {
                    "has_mal": False,
                    "has_unknown": False,
                    "first_seen": True,
                }

            # gt: ground truth label. pred: predicted label
            gt, req_text = extract_label_from_line(raw_line)
            risk = risk_score_advanced(req_text)
            
            HIGH, LOW = 12, 1
            # If rish is very high, so we mark it as malicious directly and send incident alert
            if risk >= HIGH:
                if gt == "malicious":
                    eval_stats_l1["TP"] += 1
                else:
                    eval_stats_l1["FP"] += 1
                pred = "malicious"
                latency = 0
            else:
                pred, latency = analyze_log(req_text)

            # --- LOG UNKNOWN ---
            # If the resutl is UNKNOWN, so we send incident alert and write to log about the case
            if pred == "unknown":
                
                log_missed(UNK_PATH, gt, pred, req_text)
                stats_l1["unknown"] += 1
                
                start_idx = max(0, current_idx - 4)
                context_win = all_req[start_idx:current_idx + 1]
                
                context_content = "\n".join(context_win)
                snippet_filename = f"{src_file}_line{current_idx}.txt"
                incident_queue.put({
                    "type": "unknown",
                    "file": snippet_filename,
                    "path": src_path,
                    "request": req_text,
                    "timestamp": time.time(),
                    "custom_content": context_content
                })

            # --- LOG FALSE NEGATIVE (VERY DANGER) ---
            # If the resutl is malicious, so we send incident alert and write to log about the case
            if gt == "malicious" and pred == "safe":
                eval_stats_l1["FN"] += 1
                log_missed(FN_PATH, gt, pred, req_text)

            # --- LOG FALSE POSITIVE ---
            if gt == "safe" and pred == "malicious":
                eval_stats_l1["FP"] += 1
                log_missed(FP_PATH, gt, pred, req_text)

            # Update confusion matrix
            if gt == "malicious" and pred == "malicious":
                eval_stats_l1["TP"] += 1
                # else: eval_stats_l1["FN"] += 1
            elif gt == "safe" and pred == "safe":
                eval_stats_l1["TN"] += 1
            # else: eval_stats_l1["FP"] += 1

            # === UPDATE FILE-LEVEL STATE ===
            if pred == "malicious":
                file_state[src_file]["has_mal"] = True
            elif pred == "unknown":
                file_state[src_file]["has_unknown"] = True

            # === CHỈ INCIDENT 1 LẦN CHO MỖI FILE ===
            if file_state[src_file]["first_seen"]:
                # Đánh dấu đã incident
                file_state[src_file]["first_seen"] = False

                # Đưa file vào đúng bucket ban đầu
                if file_state[src_file]["has_mal"]:
                    tag = "malicious"
                elif file_state[src_file]["has_unknown"]:
                    tag = "unknown"
                else:
                    tag = "safe"

                incident_queue.put(
                    {
                        "type": tag,
                        "file": src_file,
                        "path": src_path,
                        "request": req_text,
                        "timestamp": time.time(),
                    }
                )
            # Update stats
            stats_l1["total"] += 1
            stats_l1["latencies"].append(latency if latency is not None else 0)
            stats_l1[pred] += 1

            # if stats["total"] % UPDATE_CHART_EVERY == 0:
            #     push_stats_safe()

        except Exception as e:
            print("Worker error:", e)

        job_queue.task_done()


# Spawn workers
for _ in range(WORKER_COUNT):
    threading.Thread(target=worker, daemon=True).start()

# ==========================
# INCIDENT HANDLER
# ==========================
incident_lock = threading.Lock()


def incident_handler():
    # dùng các folder đã định nghĩa ở trên
    for d in (MALICIOUS_FOLDER, UNKNOWN_FOLDER, SAFE_FOLDER):
        os.makedirs(d, exist_ok=True)

    tag_dir_map = {
        "malicious": MALICIOUS_FOLDER,
        "unknown": UNKNOWN_FOLDER,
        "safe": SAFE_FOLDER,
    }

    while True:
        inc = incident_queue.get()

        tag = inc["type"]  # "safe" | "malicious" | "unknown"
        src = inc["path"]  # đường dẫn file log gốc

        # Ghi nội dung request ra file log theo tag, vào logs/<tag>_requests.txt
        with incident_lock:
            req_log_path = os.path.join(BASE_LOG_DIR, f"{tag}_requests.txt")
            with open(req_log_path, "a", encoding="utf-8") as f:
                f.write(
                    f"[{time.ctime(inc['timestamp'])}] "
                    f"FILE={inc['file']}\n"
                    f"{inc['request']}\n\n"
                )

        # Thư mục đích cho file gốc
        dst_dir = tag_dir_map.get(tag, UNKNOWN_FOLDER)
        os.makedirs(dst_dir, exist_ok=True)

        dst = os.path.join(dst_dir, os.path.basename(src))

        if "custom_content" in inc and inc["custom_content"]:
            try:
                with open(dst, "w", encoding="utf-8") as f:
                    f.write(inc["custom_content"])
            except Exception as e:
                print(f"[incident_handler] Lỗi ghi file context {dst}: {e}")
        else:
            src = inc["path"]
            if os.path.exists(src) and not os.path.exists(dst):
                try:
                    shutil.copy2(src, dst)
                except Exception as e:
                    print(f"[incident_handler] Lỗi copy {src} -> {dst}: {e}")
        
        incident_queue.task_done()

threading.Thread(target=incident_handler, daemon=True).start()


# ==========================
# METRIC CALCULATION
# ==========================
def calc_metrics_l1():
    TP = eval_stats_l1["TP"]
    FP = eval_stats_l1["FP"]
    TN = eval_stats_l1["TN"]
    FN = eval_stats_l1["FN"]

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    return precision, recall, f1


def calc_metrics_l2():
    TP = eval_stats_l2["TP"]
    FP = eval_stats_l2["FP"]
    TN = eval_stats_l2["TN"]
    FN = eval_stats_l2["FN"]

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    return precision, recall, f1


def calc_throughput():
    elapsed = time.time() - SYSTEM_START

    rps = throughput_stats["requests"] / elapsed if elapsed > 0 else 0
    tps = throughput_stats["tokens"] / elapsed if elapsed > 0 else 0

    return rps, tps


# ================================
# UNKNOWN SCAN
# ================================
# using LogBertAnalyzer from src/detector.py
VOCAB_SIZE = 3551
ANOMALY_THRESHOLD = 3
try:
    analyzer = LogBertAnalyzer(vocab_size=VOCAB_SIZE)
except Exception as e:
    print(f"⚠️ Không thể tải LogBertAnalyzer: {e}")
    analyzer = None

scored_files = set()

resolved_history = deque(maxlen=20)
def process_single_file(file_path, stats):
    if analyzer is None:
        return None
    
    if stats_l1["unknown"] > 0: 
        stats_l1["unknown"] -= 1

    fname = os.path.basename(file_path)
    display_content = ""
    event_ids = []
    
    try:
        with open(file_path, "r", errors="ignore") as f:
            log_req = list(parsing_http_requests(f))

            if log_req:
                display_content = log_req[-1].strip() # Lấy request cuối cùng
            else:
                display_content = Path(file_path).read_text(encoding="utf-8", errors="ignore")

            
            for log_string in log_req:
                result = process_log_string(log_string)
                e_id = result.get("EventId")
                if e_id is not None:
                    event_ids.append(e_id)
    except Exception as e:
        print(f"Lỗi đọc file {file_path}: {e}")
        return None

    if not event_ids:
        try: os.remove(file_path)
        except: pass
        return None
    
    try:
        detection_result = analyzer.detect_anomalies(event_ids, confidence_threshold=0.05)
        anomalies = detection_result.get("anomalies", [])
        target_line_id = len(event_ids)
        target_is_anomalous = False
        confidence = 1.0
        for a in anomalies:
            if a["LineId"] == target_line_id:
                target_is_anomalous = True
                confidence = a["Confidence"]
                break
        is_anomalous = target_is_anomalous
        final_verdict = ""

        fname = os.path.basename(file_path)
        final_verdict = ""
        if is_anomalous:
            final_verdict = "malicious"
            file_pred[fname] = "malicious"

            stats_l1["malicious"] += 1
            stats["malicious"] += 1

            dst = os.path.join(MALICIOUS_FOLDER, fname)
            try: shutil.move(file_path, dst)
            except: pass
            print(f"[LogBERT] {fname} -> MALICIOUS")
        else:
            final_verdict = "safe"
            file_pred[fname] = "safe"
            
            # Tăng count Safe
            stats_l1["safe"] += 1
            stats["safe"] += 1

            dst = os.path.join(SAFE_FOLDER, fname)
            try: shutil.move(file_path, dst)
            except: pass

        try:
            ground_truth = "safe"            
            if fname in file_gt:
                ground_truth = file_gt[fname]
            else:
                original_name = fname.split("_line")[0]
                if original_name in file_gt:
                    ground_truth = file_gt[original_name]
                    
            if ground_truth == "malicious" and final_verdict == "malicious":
                eval_stats_l2["TP"] += 1
            elif ground_truth == "safe" and final_verdict == "safe":
                eval_stats_l2["TN"] += 1
            elif ground_truth == "safe" and final_verdict == "malicious":
                eval_stats_l2["FP"] += 1 # Báo nhầm
            elif ground_truth == "malicious" and final_verdict == "safe":
                eval_stats_l2["FN"] += 1 # Bỏ sót

        except Exception as e:
            print(f"Lỗi tính điểm L2: {e}")
        
        resolved_history.appendleft({
            "time": time.strftime("%H:%M:%S"),
            "file": fname,
            "content": display_content,
            "status": final_verdict,
            "score": confidence
        })

    except Exception as e:
        print(f"❌ Lỗi khi chạy model cho {file_path}: {e}")


def unknow_scan_batch(stop_event, stats):
    if not os.path.exists(UNKNOWN_FOLDER):
        os.makedirs(UNKNOWN_FOLDER)

    print("LogBERT Scanner started monitoring:", UNKNOWN_FOLDER)

    while not stop_event.is_set():
        # 1. Lấy danh sách file mới nhất
        files = glob.glob(os.path.join(UNKNOWN_FOLDER, "*"))

        # 2. Lọc các file chưa check
        files_to_scan = [f for f in files if not f.endswith(".checked_anomaly")]

        if not files_to_scan:
            time.sleep(2)
            continue

        # 3. Sort theo tên (mặc định sort string đường dẫn là sort theo tên)
        files_to_scan.sort()

        # 4. Lấy file ở đầu danh sách (file cũ nhất hoặc tên nhỏ nhất tùy cách đặt tên)
        target_file = files_to_scan[0]

        try:
            # Xử lý file đầu tiên này
            if stop_event.is_set():
                break
            process_single_file(target_file, stats)

            # Lưu ý: Không dùng vòng lặp for duyệt hết list ở đây.
            # Việc quay lại đầu vòng while sẽ giúp code cập nhật lại danh sách file
            # và sort lại ngay lập tức nếu có file mới ưu tiên hơn chèn vào.

        except Exception as e:
            print(f"Error processing {target_file}: {e}")
            time.sleep(1)  # Sleep nhẹ nếu lỗi để tránh spam CPU

        # Nghỉ ngắn giữa các lần check để nhường CPU
        time.sleep(0.1)


# ==========================
# WEBSOCKET
# ==========================
async def push_stats():
    # Metrics L1
    p1, r1, f1_l1 = calc_metrics_l1()

    # Metrics L2 (file level)
    p2, r2, f1_l2 = calc_metrics_l2()

    rps, tps = calc_throughput()
    lat_vals = [x for x in stats_l1["latencies"] if isinstance(x, (int, float))]
    avg_lat = sum(lat_vals) / len(lat_vals) if lat_vals else 0
    unknown = stats_l1["unknown"]
    msg = json.dumps(
        {
            # ==========================
            # REQUEST-LEVEL (L1 SCORES)
            # ==========================
            "l1_TP": eval_stats_l1["TP"],
            "l1_TN": eval_stats_l1["TN"],
            "l1_FP": eval_stats_l1["FP"],
            "l1_FN": eval_stats_l1["FN"],
            "l1_precision": p1,
            "l1_recall": r1,
            "l1_f1": f1_l1,
            # ==========================
            # FILE-LEVEL (L2 SCORES)
            # ==========================
            "l2_TP": eval_stats_l2["TP"],
            "l2_TN": eval_stats_l2["TN"],
            "l2_FP": eval_stats_l2["FP"],
            "l2_FN": eval_stats_l2["FN"],
            "l2_precision": p2,
            "l2_recall": r2,
            "l2_f1": f1_l2,
            # ==========================
            # SYSTEM STATS
            # ==========================
            "total": stats_l1["total"],
            "safe": stats_l1["safe"],
            "malicious": stats_l1["malicious"],
            "unknown": stats_l1["unknown"],
            "rps": rps,
            "tps": tps,
            "avg_latency": avg_lat,

            "recent_logs": list(resolved_history)
        }
    )

    print("TPS", tps)
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
        time.sleep(5)  # gửi mỗi giây


threading.Thread(target=stats_pusher, daemon=True).start()

# ==========================
# MAIN SIMULATION
# ==========================


# Load logs and enqueue requests
# We will simulate the speed at which log files are generated in real time.
def start_simulation():
    files = sorted(Path(LOG_FOLDER).glob("*.txt"))

    for file in files:
        print(f"📄 Processing file: {file.name}")

        content = file.read_text(errors="ignore")
        reqs = split_requests_rfc(content, file.name)

        for i,req in enumerate(reqs):
            # We will take some infomation when scanning any request from the log file.
            job_queue.put({"file": file.name, "path": str(file), "request": req, "index": i, "all_request": reqs })
            time.sleep(random.uniform(0.01, 0.05))
        time.sleep(random.uniform(0.05, 0.2))


# ==========================
# WEBSOCKET SERVER
# ==========================
async def ws_handler(websocket):
    ws_clients.add(websocket)
    try:
        async for message in websocket:
            try:
                data = json.loads(message)

                if data.get("action") == "analyze_log":
                    log_content = data.get("content")
                    
                    await websocket.send(json.dumps({
                        "type": "analysis_result",
                        "status": "processing"
                    }))
                    
                    loop = asyncio.get_running_loop()
                    explanation = await loop.run_in_executor(
                        None, 
                        gemini_explainer.explain_anomaly, 
                        log_content
                    )
                    
                    await websocket.send(json.dumps({
                        "type": "analysis_result",
                        "status": "done",
                        "result": explanation
                    }))
                    
            except Exception as e:
                print(f"Lỗi xử lý message: {e}")
                
    finally:
        ws_clients.remove(websocket)

# async def websocket_main():
#     async with websockets.serve(ws_handler, "0.0.0.0", 8765):
#         print("WebSocket server started on ws://0.0.0.0:8765")
#         await asyncio.Future()

# def start_websocket_server():
#     global ws_loop
#     ws_loop = asyncio.new_event_loop()
#     asyncio.set_event_loop(ws_loop)
#     ws_loop.run_until_complete(websocket_main())
#     ws_loop.run_forever()


# ==========================
# ENTRY
# ==========================
async def main_async():
    
    # Start websocket server
    server = await websockets.serve(ws_handler, "0.0.0.0", 8765)

    print("WebSocket server started on ws://0.0.0.0:8765")

    # Start periodic stats pusher
    async def async_stats_pusher():
        while True:
            await push_stats()
            await asyncio.sleep(5)

    asyncio.create_task(async_stats_pusher())

    # Run simulation in background thread (non-blocking)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, start_simulation)


unknown_stop_event = threading.Event()
if __name__ == "__main__":
    # global SYSTEM_START
    SYSTEM_START = time.time()
    # start LogBERT scanner
    threading.Thread(
        target=unknow_scan_batch, args=(unknown_stop_event, stats_l2), daemon=True
    ).start()

    # start health checker
    threading.Thread(target=healthcheck, daemon=True).start()
    asyncio.run(main_async())
