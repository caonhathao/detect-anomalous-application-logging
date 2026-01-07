import os
import sys
import glob
import time
import numpy as np
from tqdm import tqdm
from dotenv import load_dotenv
from pathlib import Path

# Thêm đường dẫn root để import được các module trong src
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src import LogBertAnalyzer, parsing_http_requests, process_log_string

# ================= CONFIG =================
load_dotenv()
LOG_FOLDER = os.getenv("LOG_FOLDER", "logs") # Đảm bảo file .env có biến này hoặc sửa trực tiếp
VOCAB_SIZE = 3551
CONFIDENCE_THRESHOLD = 0.05  # Ngưỡng giống trong analyzer.py

# ================= HELPER FUNCTIONS (Copy từ analyzer.py) =================
def split_requests_rfc(content, filename):
    """Tách request và lấy nhãn Ground Truth từ file log"""
    reqs = []
    labels = [] # List chứa nhãn 'safe' hoặc 'malicious'
    current = []
    
    lines = content.splitlines()
    is_malicious = False
    
    # Biến tạm để xác định nhãn của block hiện tại
    current_label = "safe" 

    for line in lines:
        if line.strip() in ("SAFE|", "MALICIOUS|"):
            # Lưu block cũ
            if current:
                reqs.append("\n".join(current).strip())
                labels.append(current_label)
                current = []
            
            # Cập nhật nhãn mới
            if line.strip() == "MALICIOUS|":
                current_label = "malicious"
            else:
                current_label = "safe"
        else:
            current.append(line)

    # Block cuối
    if current:
        reqs.append("\n".join(current).strip())
        labels.append(current_label)

    return reqs, labels

# ================= MAIN BENCHMARK =================
def main():
    print(f"🚀 Đang khởi tạo LogBERT Analyzer (Vocab: {VOCAB_SIZE})...")
    try:
        analyzer = LogBertAnalyzer(vocab_size=VOCAB_SIZE)
    except Exception as e:
        print(f"❌ Lỗi load model: {e}")
        return

    # Lấy danh sách file log gốc
    if not os.path.exists(LOG_FOLDER):
        print(f"❌ Không tìm thấy thư mục log: {LOG_FOLDER}")
        return

    log_files = sorted(Path(LOG_FOLDER).glob("*.txt"))
    print(f"📂 Tìm thấy {len(log_files)} file log để test.")

    # Thống kê
    stats = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    total_time = 0
    total_requests = 0

    print("\n🔄 Bắt đầu chạy Benchmark...")
    
    # Duyệt qua từng file log
    for file_path in tqdm(log_files, desc="Processing Files"):
        try:
            content = file_path.read_text(errors="ignore")
            requests, labels = split_requests_rfc(content, file_path.name)
            
            # Duyệt qua từng request trong file
            for i, req_text in enumerate(requests):
                gt_label = labels[i] # safe / malicious
                
                # --- BẮT ĐẦU ĐO THỜI GIAN XỬ LÝ CỦA BERT ---
                start_time = time.time()
                
                # 1. Preprocessing (Text -> Event IDs)
                # Mô phỏng lại logic của process_single_file
                event_ids = []
                # Giả lập ghi ra file rồi đọc lại dòng (hoặc parse trực tiếp string)
                # Ở đây ta parse trực tiếp string cho nhanh
                log_lines = list(parsing_http_requests(req_text.splitlines()))
                for log_string in log_lines:
                    result = process_log_string(log_string)
                    if result.get("EventId"):
                        event_ids.append(result.get("EventId"))
                
                if not event_ids:
                    continue # Bỏ qua nếu không parse được ID nào

                # 2. Prediction
                detection_result = analyzer.detect_anomalies(event_ids, confidence_threshold=CONFIDENCE_THRESHOLD)
                
                # Logic xác định malicious giống analyzer.py
                # (Nếu dòng cuối cùng hoặc bất kỳ dòng nào trong cửa sổ bị đánh dấu là anomaly)
                # Ở đây ta lấy logic: Có bất kỳ anomaly nào trong request này -> Malicious
                is_predicted_malicious = len(detection_result.get("anomalies", [])) > 0
                
                end_time = time.time()
                # --- KẾT THÚC ĐO ---

                total_time += (end_time - start_time)
                total_requests += 1

                pred_label = "malicious" if is_predicted_malicious else "safe"

                # 3. Update Confusion Matrix
                if gt_label == "malicious" and pred_label == "malicious":
                    stats["TP"] += 1
                elif gt_label == "safe" and pred_label == "safe":
                    stats["TN"] += 1
                elif gt_label == "safe" and pred_label == "malicious":
                    stats["FP"] += 1
                elif gt_label == "malicious" and pred_label == "safe":
                    stats["FN"] += 1

        except Exception as e:
            print(f"⚠️ Lỗi xử lý file {file_path.name}: {e}")

    # ================= REPORT =================
    TP, TN, FP, FN = stats["TP"], stats["TN"], stats["FP"], stats["FN"]
    total = TP + TN + FP + FN
    
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (TP + TN) / total if total > 0 else 0
    avg_latency = (total_time / total_requests) * 1000 if total_requests > 0 else 0 # ms

    print("\n" + "="*40)
    print("📊 KẾT QUẢ BENCHMARK (BERT ONLY)")
    print("="*40)
    print(f"Total Requests: {total}")
    print(f"Avg Latency:    {avg_latency:.2f} ms/request")
    print("-" * 40)
    print(f"Confusion Matrix:")
    print(f"TP: {TP} | FP: {FP}")
    print(f"FN: {FN} | TN: {TN}")
    print("-" * 40)
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1_score:.4f}")
    print("="*40)

if __name__ == "__main__":
    main()