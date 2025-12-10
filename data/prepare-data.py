import os
import re
import urllib.parse
import json

# --- CONFIG ---
INPUT_FOLDER = "output_logs/_csic_2010_raw"
OUTPUT_FOLDER = "training_data"
TARGET_SIZE_KB = 6  # every output jsonl file ~6 KB

def preprocess_log(log_string):
    """Masking giống lúc training model"""
    try:
        # URL decode
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
    """Tạo format huấn luyện (Alpaca-style)"""
    return {
        "instruction": "Analyze the following HTTP log and determine if it is Safe or Malicious.",
        "input": log_content,
        "output": label
    }


def process_and_split():
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)

    # nhận diện begin-request
    start_pattern = re.compile(
        r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+http',
        re.IGNORECASE
    )

    files = [f for f in os.listdir(INPUT_FOLDER) if f.endswith(".txt")]

    current_chunk = []
    current_size = 0
    file_count = 1
    target_bytes = TARGET_SIZE_KB * 1024

    for file_name in files:

        # Determine label based on FILE TYPE
        # (You confirmed normal files contain only normal requests,
        #  anomalous files contain only anomaly requests)
        if "normal" in file_name.lower():
            default_label = "Safe"
        elif "anomal" in file_name.lower():
            default_label = "Malicious"
        else:
            print(f"Bỏ qua file: {file_name} (không xác định được nhãn)")
            continue

        print(f"Đang xử lý {file_name} -> Default label: {default_label}")

        with open(os.path.join(INPUT_FOLDER, file_name), "r", encoding="utf-8", errors="ignore") as f:
            buffer = []
            for line in f:

                # nếu thấy request mới
                if start_pattern.match(line):
                    if buffer:
                        raw = "".join(buffer)
                        clean = preprocess_log(raw)

                        # mỗi request là 1 sample → gán nhãn đúng theo file gốc
                        entry = create_instruction_format(clean, default_label)
                        json_str = json.dumps(entry, ensure_ascii=False) + "\n"
                        entry_size = len(json_str.encode("utf-8"))

                        # split file
                        if current_size + entry_size > target_bytes:
                            out_path = os.path.join(OUTPUT_FOLDER, f"train_part_{file_count:04d}.jsonl")
                            with open(out_path, "w", encoding="utf-8") as out:
                                out.writelines(current_chunk)
                            file_count += 1
                            current_chunk = []
                            current_size = 0

                        current_chunk.append(json_str)
                        current_size += entry_size

                    buffer = []

                buffer.append(line)

            # add last request
            if buffer:
                raw = "".join(buffer)
                clean = preprocess_log(raw)
                entry = create_instruction_format(clean, default_label)
                json_str = json.dumps(entry, ensure_ascii=False) + "\n"

                current_chunk.append(json_str)

    # Write final chunk
    if current_chunk:
        out_path = os.path.join(OUTPUT_FOLDER, f"train_part_{file_count:04d}.jsonl")
        with open(out_path, "w", encoding="utf-8") as out:
            out.writelines(current_chunk)

    print("🎉 DONE — Tạo file huấn luyện tại:", OUTPUT_FOLDER)


if __name__ == "__main__":
    if not os.path.exists(INPUT_FOLDER):
        os.makedirs(INPUT_FOLDER)
        print("Vui lòng thêm file CSIC vào INPUT_FOLDER.")
    else:
        process_and_split()
