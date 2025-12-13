import os
import random
import re

# ==========================================
# TÁCH REQUEST THEO BLOCK (CSIC 2010)
# ==========================================
REQUEST_START = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+http",
    re.IGNORECASE
)

def split_requests_from_file(path):
    """
    Đọc file log gốc và tách thành từng REQUEST BLOCK.
    Một block = nhiều dòng (Request-Line + Headers + Body).
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    blocks = []
    current_block = []

    for line in lines:
        if REQUEST_START.match(line):  # bắt đầu request mới
            if current_block:
                blocks.append("".join(current_block).rstrip() + "\n")
                current_block = []
        current_block.append(line)

    if current_block:
        blocks.append("".join(current_block).rstrip() + "\n")

    return blocks


# ==========================================
# GÁN NHÃN THEO BLOCK CHO TOÀN REQUEST
# ==========================================
def label_files_by_block(input_folder, output_folder, label_prefix):
    os.makedirs(output_folder, exist_ok=True)

    for root, _, files in os.walk(input_folder):
        for file in files:
            if not file.endswith(".txt"):
                continue

            src = os.path.join(root, file)
            dst = os.path.join(output_folder, file.replace(".txt", "_labeled.txt"))

            try:
                blocks = split_requests_from_file(src)

                with open(dst, "w", encoding="utf-8") as fout:
                    for block in blocks:
                        fout.write(f"{label_prefix}|\n")   # chỉ gán nhãn một dòng
                        fout.write(block)
                        fout.write("\n\n")  # ngăn cách block

                print(f"✅ Labeled: {file} ({len(blocks)} requests)")

            except Exception as e:
                print(f"❌ Lỗi khi gán nhãn {file}: {e}")


# ==========================================
# MERGE FILES ĐÃ LABEL
# ==========================================
def merge_files(folder_paths, output_file, history_file):
    abs_output_file = os.path.abspath(output_file)
    abs_history_file = os.path.abspath(history_file)

    processed_files = set()
    if os.path.exists(abs_history_file):
        with open(abs_history_file, "r", encoding="utf-8") as f:
            processed_files = set(line.strip() for line in f)

    files_to_process = []

    for folder in folder_paths:
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith(".txt"):
                    full_path = os.path.abspath(os.path.join(root, file))
                    if (
                        full_path not in processed_files
                        and full_path != abs_output_file
                        and full_path != abs_history_file
                    ):
                        files_to_process.append(full_path)

    if not files_to_process:
        print("🎉 Không còn file mới để merge.")
        return

    print(f"🔄 Đang trộn ngẫu nhiên {len(files_to_process)} file...")
    random.shuffle(files_to_process)

    count = 0
    with open(abs_output_file, "a", encoding="utf-8") as fout:
        for fp in files_to_process:
            try:
                with open(fp, "r", encoding="utf-8") as fin:
                    content = fin.read().rstrip()

                if content:
                    fout.write(content + "\n\n")
                    count += 1
                    print(f"📌 Merged: {os.path.basename(fp)}")

                # log history
                with open(abs_history_file, "a", encoding="utf-8") as flog:
                    flog.write(fp + "\n")

            except Exception as e:
                print(f"❌ Lỗi merge {fp}: {e}")

    print(f"🎉 Merge hoàn tất {count} file vào {output_file}")


# ==========================================
# MAIN PIPELINE
# ==========================================
if __name__ == "__main__":

    normal_folder = r"C:\\Users\\LEGION\Documents\\github\\detect-anomalous-application-logging\\logs\\csic_2010_normal_test" 
    attack_folder = r"C:\\Users\\LEGION\Documents\\github\\detect-anomalous-application-logging\\logs\\csic_2010_anomalious_test"

    labeled_normal_folder = "labeled_normal"
    labeled_attack_folder = "labeled_attack"

    merged_output = "merged_output.txt"
    merged_history = "merged_history.log"

    if os.path.exists(merged_output): os.remove(merged_output)
    if os.path.exists(merged_history): os.remove(merged_history)

    print("========== GÁN NHÃN THEO BLOCK ==========")
    label_files_by_block(normal_folder, labeled_normal_folder, "SAFE")
    label_files_by_block(attack_folder, labeled_attack_folder, "MALICIOUS")

    print("\n========== MERGE FILE ==========")
    merge_files([labeled_normal_folder, labeled_attack_folder],
                merged_output, merged_history)

    print("\n🎉 HOÀN TẤT! Dataset chuẩn RFC + nhãn đúng chuẩn!")
