import os
import re
import urllib.parse
import json

# --- CẤU HÌNH ---
INPUT_FOLDER = "output_logs/_csic_2010_raw"       # Bỏ file normalTrafficTraining.txt và anomalousTrafficTest.txt vào đây
OUTPUT_FOLDER = "training_data" # Nơi chứa các file jsonl đã chia nhỏ
TARGET_SIZE_KB = 6              # Dung lượng mỗi file con

def preprocess_log(log_string):
    """Làm sạch và Masking"""
    try:
        log_string = urllib.parse.unquote(log_string).strip()
        # Mask Session ID
        log_string = re.sub(r'(JSESSIONID=)[a-fA-F0-9]{32}', r'\1<UUID>', log_string)
        # Mask Host
        log_string = re.sub(r'http://[\w\-\.]+:\d+', 'http://<HOST>', log_string)
        log_string = re.sub(r'Host:\s+[\w\-\.]+:\d+', 'Host: <HOST>', log_string)
        return log_string
    except:
        return log_string

def create_instruction_format(log_content, label):
    """Tạo format huấn luyện cho Llama 3 (Alpaca style)"""
    return {
        "instruction": "Analyze the following HTTP log and determine if it is Safe or Malicious.",
        "input": log_content,
        "output": label
    }

def process_and_split():
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
    
    # Regex nhận diện đầu log
    log_start_pattern = re.compile(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+http', re.IGNORECASE)
    
    files = [f for f in os.listdir(INPUT_FOLDER) if f.endswith('.txt')]
    
    current_chunk = []
    current_size = 0
    file_count = 1
    target_bytes = TARGET_SIZE_KB * 1024

    for file_name in files:
        # Tự động gán nhãn dựa trên tên file CSIC
        if "normal" in file_name.lower():
            label = "Safe"
        elif "anomal" in file_name.lower():
            label = "Malicious"
        else:
            print(f"Bỏ qua file {file_name} vì không xác định được nhãn.")
            continue
            
        print(f"Đang xử lý: {file_name} -> Nhãn: {label}")
        
        path = os.path.join(INPUT_FOLDER, file_name)
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            buffer = []
            for line in f:
                if log_start_pattern.match(line):
                    if buffer:
                        raw_log = "".join(buffer)
                        clean_log = preprocess_log(raw_log)
                        
                        # Tạo JSON object
                        json_entry = create_instruction_format(clean_log, label)
                        json_str = json.dumps(json_entry, ensure_ascii=False) + "\n"
                        entry_size = len(json_str.encode('utf-8'))

                        # Kiểm tra dung lượng để tách file
                        if current_size + entry_size > target_bytes and current_size > 0:
                            # Ghi ra file
                            out_name = os.path.join(OUTPUT_FOLDER, f"train_part_{file_count:04d}.jsonl")
                            with open(out_name, 'w', encoding='utf-8') as out_f:
                                out_f.writelines(current_chunk)
                            file_count += 1
                            current_chunk = []
                            current_size = 0
                        
                        current_chunk.append(json_str)
                        current_size += entry_size
                        buffer = []
                buffer.append(line)
            
            # Xử lý log cuối cùng
            if buffer:
                raw_log = "".join(buffer)
                clean_log = preprocess_log(raw_log)
                json_entry = create_instruction_format(clean_log, label)
                current_chunk.append(json.dumps(json_entry, ensure_ascii=False) + "\n")

    # Ghi file cuối cùng
    if current_chunk:
        out_name = os.path.join(OUTPUT_FOLDER, f"train_part_{file_count:04d}.jsonl")
        with open(out_name, 'w', encoding='utf-8') as out_f:
            out_f.writelines(current_chunk)
            
    print(f"Xong! Dữ liệu đã chia nhỏ tại folder '{OUTPUT_FOLDER}'")

if __name__ == "__main__":
    if not os.path.exists(INPUT_FOLDER):
        os.makedirs(INPUT_FOLDER)
        print(f"Hãy tạo folder '{INPUT_FOLDER}' và copy file CSIC vào đó.")
    else:
        process_and_split()