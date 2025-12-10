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
# CONFIG — CSIC HYBRID MODE vA6 (Balanced)
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
# CSIC STRUCTURAL RULES — HEURISTIC SCORING
# ============================================

# Expected CSIC URL path pattern
CSIC_URL_PATTERN = re.compile(r"/tienda1/publico/.*\.jsp", re.IGNORECASE)

# Typical CSIC parameter names
EXPECTED_PARAMS = ["id", "nombre", "precio", "cantidad"]

def decode_safe(s):
    try:
        return urllib.parse.unquote_plus(s)
    except:
        return s

def csic_heuristic_score(text):
    """
    Structural scoring for CSIC 2010 logs (Balanced Mode)
    Range: 0–10 points
    """
    score = 0
    lines = text.split("\n")

    # Extract request line
    req = lines[0].strip() if lines else ""
    req_l = req.lower()

    # 1) Check method
    if not (req_l.startswith("get ") or req_l.startswith("post ")):
        score += 1.5

    # 2) Check URL structure
    if "http://" not in req_l or "tienda1/publico" not in req_l:
        score += 2.0

    # 3) Validate .jsp structured path
    if CSIC_URL_PATTERN.search(req_l) is None:
        score += 1.5

    # 4) Parameter extraction
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
                    score += 1.0  # malformed key-value

            # 5) Missing expected params
            for ep in EXPECTED_PARAMS:
                if ep not in param_names:
                    score += 0.8

            # 6) Parameter count anomaly
            if len(param_names) != len(EXPECTED_PARAMS):
                score += 1.0

            # 7) Parameter value anomalies
            for p in params:
                if "=" in p:
                    k, v = p.split("=", 1)
                    v_dec = decode_safe(v)

                    # numeric anomalies
                    if k == "id":
                        if not v_dec.isdigit():
                            score += 1.0
                        elif int(v_dec) > 20:
                            score += 1.0

                    if k == "precio":
                        try:
                            if float(v_dec) > 100:
                                score += 1.0
                        except:
                            score += 1.0

                    # weird patterns
                    if re.search(r"[%]{3,}", v):
                        score += 1.5

                    if len(v) > 60:
                        score += 1.2

    # 8) Header anomalies
    headers = [h.lower() for h in lines[1:15]]
    required = ["user-agent", "accept", "accept-charset", "accept-language"]

    for r in required:
        if not any(h.startswith(r) for h in headers):
            score += 1.0

    # 9) Cookie validation (CSIC cookies always hex)
    for h in headers:
        if h.startswith("cookie:"):
            cookie = h.split(":", 1)[1]
            if "jsessionid" in cookie.lower():
                js = cookie.split("=")[1].strip()
                if not re.match(r"^[A-F0-9]{32}$", js, re.I):
                    score += 1.0

    # 10) Long-line anomaly
    for line in lines:
        if len(line) > 200:
            score += 1.0

    return min(score, 10.0)


# ============================================
# AI PROMPT (Confirm Only for Ambiguous Cases)
# ============================================

AI_PROMPT = """
You are an intrusion detection model specialized in CSIC 2010 dataset.

Mark a request as MALICIOUS (1) if:
- Structure deviates from typical CSIC patterns
- Missing mandatory headers
- Improper parameter order or invalid parameter content
- Suspicious encodings or malformed URL
- Numeric parameters far outside expected ranges
- Header inconsistencies or missing JSESSIONID
- Abnormal request line structure
- Path not matching /tienda1/publico/*.jsp
- ANYTHING that deviates from normal behavior

Return ONLY:
1 = Malicious
0 = Normal
""".strip()

# ============================================
# AI Evaluation + HYBRID DECISION
# ============================================

AI_LOW = 2.0        # Under this → SAFE
AI_HIGH = 4.0       # Above this → MALICIOUS

def ai_eval(filename, content, idx):
    t0 = time.time()

    # 1️⃣ Heuristic scoring (CSIC-based)
    score = csic_heuristic_score(content)

    # -- Direct malignant
    if score >= AI_HIGH:
        return {"file": filename, "malicious": True, "latency": time.time()-t0, "status": f"Heur({score})"}

    # -- Direct safe
    if score < AI_LOW:
        return {"file": filename, "malicious": False, "latency": time.time()-t0, "status": f"SafeHeur({score})"}

    # 2️⃣ Ambiguous → Ask AI
    compressed = content[:2000]  # minimal reduction for CSIC
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
                "status": f"AI(score={score})"
            }

        except:
            time.sleep(BACKOFF[r])

    # Final fallback
    return {"file": filename, "malicious": True, "latency": time.time()-t0, "status": f"Timeout({score})"}


# ============================================
# CHARTS
# ============================================

def init_chart():
    plt.ion()
    fig, (ax1, ax2) = plt.subplots(1,2, figsize=(12,4))
    fig.canvas.manager.set_window_title("📊 ENGINE vA6 HYBRID – Realtime Stats")
    return fig, ax1, ax2

def update_chart(fig, ax1, ax2, lat, safe, mal):
    ax1.clear()
    ax2.clear()

    if len(lat) > 1:
        ax1.plot(lat[-200:], color="blue")
        ax1.set_ylim(bottom=0)
        ax1.set_title(f"Latency avg={sum(lat)/len(lat):.3f}s")

    ax2.pie([safe, mal], labels=["Safe","Malicious"], autopct="%1.1f%%",
            colors=["#4CAF50","#F44336"])
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
    print(f"📂 Found {total} files (HYBRID vA6-CSIC Mode)")

    fig, ax1, ax2 = init_chart()
    lat_list = []
    safe = 0
    mal = 0

    t0 = time.time()

    with ThreadPoolExecutor(max_workers=NUM_THREADS) as pool:
        futures = {}
        idx = 0
        file_iter = iter(files)

        # Prefill
        while len(futures) < NUM_THREADS:
            try:
                fp = next(file_iter)
                content = open(fp, "r", errors="ignore").read()
                fut = pool.submit(ai_eval, os.path.basename(fp), content, idx)
                futures[fut] = fp
                idx += 1
            except StopIteration:
                break

        pbar = tqdm(total=total, desc="Scanning (vA6)...")

        # Streaming loop
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

            if res["malicious"]:
                mal += 1
            else:
                safe += 1

            lat_list.append(res["latency"])

            if len(lat_list) % 25 == 0:
                update_chart(fig, ax1, ax2, lat_list, safe, mal)

            pbar.update(1)

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

    print("\n===== SUMMARY (HYBRID vA6 CSIC MODE) =====")
    print(f"Total files: {total}")
    print(f"Malicious : {mal}")
    print(f"Safe      : {safe}")
    print(f"Time      : {t1 - t0:.2f}s")
    print(f"Speed     : {total / (t1 - t0):.2f} files/s")

    plt.ioff()
    plt.show()


if __name__ == "__main__":
    run_engine()
