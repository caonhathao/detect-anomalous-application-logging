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
#CONFIG
# ===============================
LOG_FOLDER = os.getenv("LOG_FOLDER")
NUM_THREADS = 8
MAX_FILES = 999999
TIMEOUT = 3
MAX_RETRIES = 3
BACKOFF = [0.3, 0.6, 1.0]

# Get URL from .env
raw_urls = os.getenv("API_URLS")
if not raw_urls: 
    print("❌ Error: API_URLS not found in file .env")
    exit(1)

url_list = [u.strip() for u in raw_urls.split(",") if u.strip()]
clients = [OpenAI(base_url=u, api_key="sk-no-key-needed") for u in url_list]

if not LOG_FOLDER:
    raise ValueError("LOG_FOLDER environment variable not set")
    exit(1)

# ===============================
# 1. PREPROCESSING (MUST MATCH 100% WITH TRAINING)
# ===============================
def preprocess_inference(log_string):
    try:
        # [IMPORTANT]: If you used raw logs (not yet decoded) during training, comment out this line.
        # If you cleaned data using this function during training, keep it as is.
        log_string = urllib.parse.unquote(log_string) 
        # Mask Session ID 
        log_string = re.sub(r'(JSESSIONID=)[a-fA-F0-9]{32}', r'\1<UUID>', log_string) 
        # Mask Host URL 
        log_string = re.sub(r'http://[\w\-.]+:\d+', 'http://<HOST>', log_string) 
        # Mask Host Header 
        log_string = re.sub(r'Host:\s+[\w\-.]+:\d+', 'Host: <HOST>', log_string) 
        return log_string.strip() 
    except Exception: 
        return log_string.strip()

# ===============================
#2. PROMPT TEMPLATE (ALPACA STANDARD)
# ===============================
    
# This is the default template for json {"instruction":..., "input":...}
# If you use another template, edit this string to match each character.
PROMPT_TEMPLATE = """Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.

### Instructions:
{instruction}

### Input:
{input_log}

### Response:
"""

AI_INSTRUCTION = "Analyze the following HTTP log and determine if it is Safe or Malicious. You MUST answer with EXACTLY ONE WORD: Safe or Malicious."

# ===============================
# 3. AI EVALUATION (USING COMPLETION API)
# ===============================
def ai_eval(filename, content, idx):
    t0 = time.time()
    # 1. Clean input data
    cleaned_log = preprocess_inference(content)
    # 2. Match to standard template (Text Completion)
    # The model will see the correct structure it has learned
    full_prompt = PROMPT_TEMPLATE.format(
    instruction=AI_INSTRUCTION,
    input_log=cleaned_log
    )

    client = clients[idx % len(clients)]

    for r in range(MAX_RETRIES):
        try:
            # Use completions.create(Text) instead of chat.completions(Chat)
            response = client.completions.create(
                model="koboldcpp",
                prompt=full_prompt, # Send formatted text string
                max_tokens=10, # Only a few tokens needed for the answer
                temperature=0, # Temperature 0 for consistent results
                timeout=TIMEOUT,
                stop=["\n", "###"] # Stop immediately at line break or new header
            )
            # Get the returned text
            raw_out = response.choices[0].text.strip()  
            out = raw_out.lower()
            # More rigorous checking logic
            if "malicious" in out:
                label = True
                status_text = "AI:Malicious"
            elif "safe" in out:
                label = False
                status_text = "AI:Safe"
            else:
                # In case the model returns garbage or incorrect format
                # Default is Malicious (Fail-safe) or False depending on strategy
                label = True
                status_text = f"AI:Unknown({raw_out})"
            return {
                "file": filename,
                "malicious": label,
                "latency": time.time() - t0, 
                "status": status_text 
            }
        except Exception as e: 
            # print(f"Error: {e}") # Turn on if you want to debug 
            time.sleep(BACKOFF[r]) 
            
    return { 
        "file": filename, 
        "malicious": True, # Timeout -> treated as Malicious 
        "latency": time.time() - t0, 
        "status": "TIMEOUT" 
    }

# ===============================
# CHART & MAIN
# ===============================
def initial_chart(): 
    plt.ion() 
    fig, (ax1, ax2) = plt.subplots(1,2, figsize=(12,4)) 
    fig.canvas.manager.set_window_title("📊 ENGINE v8-FINAL (Fixed) – Realtime Stats") 
    return fig, ax1, ax2

def update_chart(fig, ax1, ax2, lat_list, safe, mal): 
    ax1.clear() 
    ax2.clear() 
    if len(lat_list) > 1: 
        ax1.plot(lat_list[-200:], color="blue") 
        ax1.set_ylim(bottom=0) 
        ax1.set_title(f"Latency avg={sum(lat_list)/len(lat_list):.3f}s") 

    total = safe + mal 
    if total > 0: 
        ax2.pie([safe, mal], labels=["Safe","Malicious"], 
            autopct="%1.1f%%", colors=["#4CAF50","#F44336"]) 

    fig.tight_layout() 
    fig.canvas.draw() 
    fig.canvas.flush_events() 
    plt.pause(0.001)

def run_engine(): 
    files = sorted(glob.glob(f"{LOG_FOLDER}/*.txt") + glob.glob(f"{LOG_FOLDER}/*.log")) 
    total = min(len(files), MAX_FILES) 
    print(f"📂 Found {total} files (ENGINE v8-FIXED)") 

    fig,ax1, ax2 = initial_chart() 
    lat = [] 
    safe = 0 
    mal = 0 
    t0 = time.time() 

    with ThreadPoolExecutor(max_workers=NUM_THREADS) as pool: 
        futures = {} 
        idx = 0 
        file_iter = iter(files) 

        # Prefill threads 
        while len(futures) < NUM_THREADS: 
            try: 
                fp = next(file_iter) 
                # Read files 
                content = open(fp, "r", errors="ignore").read() 
                fut = pool.submit(ai_eval, os.path.basename(fp), content, idx) 
                futures[fut] = fp 
                idx += 1 
            except StopIteration: 
                break

        pbar = tqdm(total=total, desc="Scanning...") 

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
    print("\n===== SUMMARY (ENGINE v8-FIXED) =====") 
    print(f"Total : {total}") 
    print(f"Malicious : {mal}") 
    print(f"Safe : {safe}") 
    print(f"Time : {t1 - t0:.2f}s") 
    if t1 - t0 > 0: 
        print(f"Speed ​​: {total/(t1 - t0):.2f} files/s") 

    plt.ioff() 
    plt.show()

if __name__ == "__main__": 
    run_engine()