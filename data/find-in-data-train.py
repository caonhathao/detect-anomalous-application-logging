import os
import json
import sys
import time

# --- CẤU HÌNH ---
SEARCH_FOLDER = "training_data"   # Thư mục chứa file .jsonl
SEARCH_TERM = "POST http://<HOST>/tienda1/miembros/editar.jsp HTTP/1.1"      # Chuỗi cần tìm
CASE_SENSITIVE = False            # True: phân biệt hoa thường

def highlight_text(text, term):
    """Tô màu đỏ cho từ khóa tìm thấy"""
    if not term: return text
    if CASE_SENSITIVE:
        return text.replace(term, f"\033[91m{term}\033[0m")
    else:
        import re
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        return pattern.sub(lambda m: f"\033[91m{m.group(0)}\033[0m", text)

def print_progress(current, total, filename):
    """Hàm vẽ thanh tiến trình"""
    percent = 100 * (current / float(total))
    bar_length = 30
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    
    # Xóa dòng hiện tại và ghi đè lên
    # \r đưa con trỏ về đầu dòng
    sys.stdout.write(f"\r⏳ [{bar}] {percent:.1f}% | Đang quét: {filename[:30]:<30}")
    sys.stdout.flush()

def clear_line():
    """Xóa dòng hiện tại (để in kết quả tìm kiếm cho sạch)"""
    sys.stdout.write("\r" + " " * 100 + "\r")
    sys.stdout.flush()

def search_in_jsonl():
    if not os.path.exists(SEARCH_FOLDER):
        print(f"❌ Thư mục '{SEARCH_FOLDER}' không tồn tại.")
        return

    print(f"🔍 BẮT ĐẦU TÌM KIẾM: '{SEARCH_TERM}' trong thư mục '{SEARCH_FOLDER}'\n")
    
    files = [f for f in os.listdir(SEARCH_FOLDER) if f.endswith(".jsonl")]
    total_files = len(files)
    
    if total_files == 0:
        print("⚠️ Không tìm thấy file .jsonl nào.")
        return

    total_matches = 0
    files_with_matches = 0
    start_time = time.time()

    for idx, file_name in enumerate(files):
        # 1. Cập nhật tiến trình
        print_progress(idx + 1, total_files, file_name)
        
        file_path = os.path.join(SEARCH_FOLDER, file_name)
        found_in_file = False
        matches_in_this_file = []

        # 2. Đọc và tìm kiếm
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_idx, line in enumerate(f):
                    line_content = line.strip()
                    check_content = line_content if CASE_SENSITIVE else line_content.lower()
                    check_term = SEARCH_TERM if CASE_SENSITIVE else SEARCH_TERM.lower()

                    if check_term in check_content:
                        found_in_file = True
                        total_matches += 1
                        
                        # Xử lý nội dung để in ra (Parse JSON)
                        display_text = ""
                        try:
                            data = json.loads(line_content)
                            display_text = f"   (Dòng {line_idx + 1})"
                            for key, value in data.items():
                                str_val = str(value)
                                check_val = str_val if CASE_SENSITIVE else str_val.lower()
                                if check_term in check_val:
                                    # Highlight và cắt ngắn
                                    val_high = highlight_text(str_val[:150], SEARCH_TERM)
                                    if len(str_val) > 150: val_high += "..."
                                    display_text += f"\n     └─ [\033[93m{key}\033[0m]: {val_high}"
                        except:
                            # Fallback nếu không parse được JSON
                            display_text = f"   (Dòng {line_idx + 1}) Raw: {highlight_text(line_content[:100], SEARCH_TERM)}..."
                        
                        matches_in_this_file.append(display_text)

        except Exception as e:
            clear_line()
            print(f"⚠️ Lỗi đọc file {file_name}: {e}")

        # 3. Nếu tìm thấy trong file này -> In ra màn hình
        if found_in_file:
            clear_line() # Xóa thanh loading để in kết quả
            print(f"📄 \033[94m{file_name}\033[0m - Tìm thấy {len(matches_in_this_file)} vị trí:")
            for m in matches_in_this_file:
                print(m)
            print("-" * 40) # Dòng ngăn cách
            
            # Sau khi in xong kết quả, loop sẽ quay lại đầu và vẽ lại thanh loading mới

        if found_in_file:
            files_with_matches += 1

    # Kết thúc
    clear_line()
    elapsed = time.time() - start_time
    print(f"✅ HOÀN TẤT trong {elapsed:.2f}s")
    print(f"📊 Tổng kết: Tìm thấy \033[91m{total_matches}\033[0m kết quả trong {files_with_matches}/{total_files} file.")

if __name__ == "__main__":
    search_in_jsonl()