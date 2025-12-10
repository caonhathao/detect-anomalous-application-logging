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

# ===============================
# CONFIG — ENGINE v8 (AI-ONLY + EXACT TRAIN MASKING)
# ===============================
LOG_FOLDER = os.getenv("LOG_FOLDER")
NUM_THREADS = 8
MAX_FILES = 999999
TIMEOUT = 3
MAX_RETRIES = 3
BACKOFF = [0.3, 0.6, 1.0]

API_URLS = [
    "http://localhost:5001/v1",
    "http://localhost:5002/v1"
]

clients = [OpenAI(base_url=u, api_key="sk-none") for u in API_URLS]

if not LOG_FOLDER:
    raise ValueError("LOG_FOLDER environment variable not set")
    exit(1)

# ===============================
# MASKING EXACTLY LIKE TRAINING
# ===============================

def preprocess_inference(log_string):
    """ EXACT masking like training data """
    try:
        # 1) URL decode
        log_string = urllib.parse.unquote(log_string)

        # 2) Mask Session ID
        log_string = re.sub(
            r'(JSESSIONID=)[a-fA-F0-9]{32}',
            r'\1<UUID>',
            log_string
        )

        # 3) Mask Host in URL
        log_string = re.sub(
            r'http://[\w\-.]+:\d+',
            'http://<HOST>',
            log_string
        )

        # 4) Mask Host header
        log_string = re.sub(
            r'Host:\s+[\w\-.]+:\d+',
            'Host: <HOST>',
            log_string
        )

        return log_string.strip()

    except Exception:
        return log_string.strip()


# ===============================
# AI PROMPT
# ===============================

AI_PROMPT = """
Instruction: Analyze the following HTTP log and determine if it is Safe or Malicious.

You MUST answer with EXACTLY ONE WORD:
- Safe
- Malicious

Do NOT explain. Do NOT add anything else.
""".strip()



# ===============================
# AI EVALUATION
# ===============================

def ai_eval(filename, content, idx):
    t0 = time.time()

    # Apply SAME masking as training
    cleaned = preprocess_inference(content)

    client = clients[idx % len(clients)]

    for r in range(MAX_RETRIES):
        try:
            response = client.chat.completions.create(
                model="koboldcpp",
                messages=[
                    {"role": "system", "content": AI_PROMPT},
                    {"role": "user", "content": cleaned}
                ],
                max_tokens=5,
                temperature=0,
                timeout=TIMEOUT,
                extra_body={"stop": ["\n"]}
            )

            out = response.choices[0].message.content.strip().lower()

            if "malicious" in out:
                label = True
            elif "safe" in out:
                label = False
            else:
                # fallback nếu model trả undefined
                label = True

            return {
                "file": filename,
                "malicious": label,
                "latency": time.time() - t0,
                "status": f"AI:{out}"
            }

        except Exception:
            time.sleep(BACKOFF[r])

    # fallback
    return {
        "file": filename,
        "malicious": True,
        "latency": time.time() - t0,
        "status": "TIMEOUT"
    }



# ===============================
# CHART
# ===============================

def init_chart():
    plt.ion()
    fig, (ax1, ax2) = plt.subplots(1,2, figsize=(12,4))
    fig.canvas.manager.set_window_title("📊 ENGINE v8-FINAL – Realtime Stats")
    return fig, ax1, ax2

def update_chart(fig, ax1, ax2, lat_list, safe, mal):
    ax1.clear()
    ax2.clear()

    if len(lat_list) > 1:
        ax1.plot(lat_list[-200:], color="blue")
        ax1.set_ylim(bottom=0)
        ax1.set_title(f"Latency avg={sum(lat_list)/len(lat_list):.3f}s")

    ax2.pie([safe, mal], labels=["Safe","Malicious"],
            autopct="%1.1f%%", colors=["#4CAF50","#F44336"])

    fig.tight_layout()
    fig.canvas.draw()
    fig.canvas.flush_events()
    plt.pause(0.001)


# ===============================
# MAIN STREAMING ENGINE
# ===============================

def run_engine():
    files = sorted(glob.glob(f"{LOG_FOLDER}/*.txt") +
                   glob.glob(f"{LOG_FOLDER}/*.log"))

    total = min(len(files), MAX_FILES)
    print(f"📂 Found {total} files (ENGINE v8-FINAL)")

    fig, ax1, ax2 = init_chart()
    lat = []
    safe = 0
    mal = 0

    t0 = time.time()

    with ThreadPoolExecutor(max_workers=NUM_THREADS) as pool:
        futures = {}
        idx = 0
        file_iter = iter(files)

        # Prefill 8 threads
        while len(futures) < NUM_THREADS:
            try:
                fp = next(file_iter)
                content = open(fp, "r", errors="ignore").read()
                fut = pool.submit(ai_eval, os.path.basename(fp), content, idx)
                futures[fut] = fp
                idx += 1
            except StopIteration:
                break

        pbar = tqdm(total=total, desc="Scanning (v8-FINAL)...")

        while futures:
            done = next((f for f in futures if f.done()), None)

            if not done:
                time.sleep(0.01)
                continue

            res = done.result()
            futures.pop(done)

            if res["malicious"]: mal += 1
            else: safe += 1

            lat.append(res["latency"])

            if len(lat) % 20 == 0:
                update_chart(fig, ax1, ax2, lat, safe, mal)

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

    print("\n===== SUMMARY (ENGINE v8-FINAL) =====")
    print(f"Total files: {total}")
    print(f"Malicious : {mal}")
    print(f"Safe      : {safe}")
    print(f"Time      : {t1 - t0:.2f}s")
    print(f"Speed     : {total/(t1 - t0):.2f} files/s")

    plt.ioff()
    plt.show()


if __name__ == "__main__":
    run_engine()
