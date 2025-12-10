import os
import re
import glob
import time
import urllib.parse
import matplotlib.pyplot as plt
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

# ============================================
# CONFIG — HYBRID MODE vA6.1 (CSIC Optimized)
# ============================================
LOG_FOLDER = os.getenv("LOG_FOLDER", "./logs_data")
NUM_THREADS = 8
MAX_FILES = 999999
MAX_RETRIES = 4
BACKOFF = [0.3, 0.6, 1.2, 2.0]

API_URLS = [
    "http://localhost:5001/v1",
    "http://localhost:5002/v1",
]

clients = [OpenAI(base_url=u, api_key="sk-none") for u in API_URLS]


# ============================================
# DYNAMIC THRESHOLD FOR AI CONFIRM (vA6.1)
# ============================================
def dynamic_ai_low(text):
    length = len(text)

    # CSIC NORMAL: 500–1100 bytes
    # CSIC ANOMALY: 200–900 bytes (trùng một phần!)
    # -> length cannot separate clearly.

    # Instead, rely on "structural score mildness":
    base = 2.0

    # Short requests (very common anomalous)
    if length < 450:
        return base - 0.4   # 1.6

    # Slightly short or slightly long (often abnormal)
    if length < 700:
        return base - 0.2   # 1.8

    # Normal range
    if length < 1200:
        return base         # 2.0

    # Long requests are suspicious
    if length < 1600:
        return base - 0.2   # 1.8

    # Very long
    return base - 0.5        # 1.5


AI_HIGH = 5.2  # unchanged for balanced mode


# ============================================
# CSIC STRUCTURAL SCORING (vA6 Improved)
# ============================================

CSIC_URL_PATTERN = re.compile(r"/tienda1/publico/.*\.jsp", re.IGNORECASE)
EXPECTED_PARAMS = ["id", "nombre", "precio", "cantidad"]

def decode_safe(s):
    try:
        return urllib.parse.unquote_plus(s)
    except:
        return s

def csic_heuristic_score(text):
    score = 0
    lines = text.split("\n")

    # -------------------------
    # 1) REQUEST LINE CHECK
    # -------------------------
    req = lines[0].strip() if lines else ""
    req_l = req.lower()

    if not (req_l.startswith("get ") or req_l.startswith("post ")):
        score += 1.5

    if "http://" not in req_l:
        score += 1.0

    if "tienda1/publico" not in req_l:
        score += 2.0

    if CSIC_URL_PATTERN.search(req_l) is None:
        score += 1.0

    # -------------------------
    # 2) PARAMETER CHECK
    # -------------------------
    if "?" in req:
        url_part = req.split(" ")[1]
        if "?" in url_part:
            query = url_part.split("?", 1)[1]
            params = query.split("&")

            param_names = []
            for p in params:
                if "=" in p:
                    k, v = p.split("=", 1)
                    param_names.append(k)
                else:
                    score += 1.0  # malformed pairs

            # missing expected parameters
            for ep in EXPECTED_PARAMS:
                if ep not in param_names:
                    score += 0.8

            # parameter count mismatch
            if len(param_names) != len(EXPECTED_PARAMS):
                score += 1.2

            # specific parameter anomalies
            for p in params:
                if "=" not in p:
                    continue

                k, v = p.split("=", 1)
                v_dec = decode_safe(v)

                if k == "id":
                    if not v_dec.isdigit() or int(v_dec) > 20:
                        score += 1.0

                elif k == "precio":
                    try:
                        if float(v_dec) > 100:
                            score += 1.0
                    except:
                        score += 1.0

                # abnormal encoding patterns
                if re.search(r"%[A-F0-9]{2}%[A-F0-9]{2}", v):
                    score += 1.0

                if len(v) > 60:
                    score += 1.0

    # -------------------------
    # 3) HEADER CHECK
    # -------------------------
    headers = [h.lower() for h in lines[1:20]]
    required_hdr = ["user-agent", "accept", "accept-charset", "accept-language"]

    for r in required_hdr:
        if not any(h.startswith(r) for h in headers):
            score += 1.0

    # Check JSESSIONID validity (hex)
    for h in headers:
        if h.startswith("cookie:"):
            cookie = h.split(":", 1)[1]
            if "jsessionid" in cookie.lower():
                js = cookie.split("=")[1].strip()
                if not re.match(r"^[A-F0-9]{32}$", js, re.I):
                    score += 1.5

    # -------------------------
    # 4) STRUCTURAL ANOMALIES
    # -------------------------
    for line in lines:
        if len(line) > 200:
            score += 1.0

    return min(score, 10.0)


# ============================================
# AI PROMPT (Confirmation Layer)
# ============================================

AI_PROMPT = """
You are an intrusion detection system specialized in CSIC 2010 traffic.

Mark request as MALICIOUS (1) if:
- Structure deviates from normal CSIC format
- Missing mandatory headers
- Parameter count mismatch
- Parameter values outside expected range
- Suspicious or unusual encoding
- Request path invalid for /tienda1/publico/*.jsp
- Anomalous HTTP structure or malformed format

Return only:
1 = MALICIOUS
0 = NORMAL
""".strip()


# ============================================
# HYBRID DECISION ENGINE vA6.1
# ============================================

def ai_eval(filename, content, idx):

    t0 = time.time()

    # 1️⃣ Heuristic scoring
    score = csic_heuristic_score(content)
    AI_LOW = dynamic_ai_low(content)

    # SAFE region
    if score < AI_LOW:
        return {
            "file": filename,
            "malicious": False,
            "latency": time.time() - t0,
            "status": f"SAFE(score={score:.2f},low={AI_LOW:.2f})"
        }

    # MALICIOUS region
    if score >= AI_HIGH:
        return {
            "file": filename,
            "malicious": True,
            "latency": time.time() - t0,
            "status": f"MAL(score={score:.2f},high={AI_HIGH})"
        }

    # 2️⃣ Ambiguous region → AI confirm
    compressed = content[:2000]
    client = clients[idx % len(clients)]

    for r in range(MAX_RETRIES):
        try:
            ai_start = time.time()

            response = client.chat.completions.create(
                model="koboldcpp",
                messages=[
                    {"role": "system", "content": AI_PROMPT},
                    {"role": "user", "content": f"REQUEST:\n{compressed}\n\nCheck:"}
                ],
                max_tokens=1,
                temperature=0.0,
                timeout=3,
                extra_body={"stop": ["\n"]}
            )

            model_out = response.choices[0].message.content.strip()
            malicious = ("1" in model_out)

            return {
                "file": filename,
                "malicious": malicious,
                "latency": time.time() - t0,
                "status": f"AI(score={score:.2f})"
            }

        except:
            time.sleep(BACKOFF[r])

    # Fallback
    return {
        "file": filename,
        "malicious": True,
        "latency": time.time() - t0,
        "status": f"TIMEOUT(score={score:.2f})"
    }


# ============================================
# CHARTS
# ============================================

def init_chart():
    plt.ion()
    fig, (ax1, ax2) = plt.subplots(1,2, figsize=(12,4))
    fig.canvas.manager.set_window_title("📊 ENGINE vA6.1 HYBRID – Realtime Stats")
    return fig, ax1, ax2

def update_chart(fig, ax1, ax2, lat, safe, mal):
    ax1.clear()
    ax2.clear()

    if len(lat) > 1:
        ax1.plot(lat[-200:], color="blue")
        ax1.set_ylim(bottom=0)
        ax1.set_title(f"Latency avg={sum(lat)/len(lat):.3f}s")

    ax2.pie([safe, mal], labels=["Safe","Malicious"],
            autopct="%1.1f%%", colors=["#4CAF50","#F44336"])

    fig.tight_layout()
    fig.canvas.draw()
    fig.canvas.flush_events()
    plt.pause(0.001)


# ============================================
# MAIN STREAMING ENGINE
# ============================================

def run_engine():
    files = sorted(glob.glob(f"{LOG_FOLDER}/*.txt") + 
                   glob.glob(f"{LOG_FOLDER}/*.log"))

    total = min(len(files), MAX_FILES)
    print(f"📂 Found {total} files (HYBRID vA6.1 CSIC Mode)")

    fig, ax1, ax2 = init_chart()
    lat_list = []
    safe = 0
    mal = 0

    t0 = time.time()

    with ThreadPoolExecutor(max_workers=NUM_THREADS) as pool:
        futures = {}
        idx = 0
        file_iter = iter(files)

        # initial batch
        while len(futures) < NUM_THREADS:
            try:
                fp = next(file_iter)
                content = open(fp, "r", errors="ignore").read()
                fut = pool.submit(ai_eval, os.path.basename(fp), content, idx)
                futures[fut] = fp
                idx += 1
            except StopIteration:
                break

        pbar = tqdm(total=total, desc="Scanning (vA6.1)...", unit="file")

        # streaming loop
        while futures:
            done = None
            for fut in futures:
                if fut.done():
                    done = fut
                    break

            if not done:
                time.sleep(0.01)
                continue

            res = done.result()
            futures.pop(done)

            # update stats
            if res["malicious"]: mal += 1
            else: safe += 1

            lat_list.append(res["latency"])

            if len(lat_list) % 25 == 0:
                update_chart(fig, ax1, ax2, lat_list, safe, mal)

            pbar.update(1)

            # submit next file
            try:
                fp = next(file_iter)
                content = open(fp, "r", errors="ignore").read()
                fut = pool.submit(ai_eval, os.path.basename(fp), content, idx)
                futures[fut] = fp
                idx += 1
            except StopIteration:
                pass

        pbar.close()

    t1 = time.time()

    print("\n===== SUMMARY (HYBRID vA6.1 CSIC MODE) =====")
    print(f"Total files: {total}")
    print(f"Malicious : {mal}")
    print(f"Safe      : {safe}")
    print(f"Time      : {t1 - t0:.2f}s")
    print(f"Speed     : {total/(t1 - t0):.2f} files/s")

    plt.ioff()
    plt.show()


if __name__ == "__main__":
    run_engine()
