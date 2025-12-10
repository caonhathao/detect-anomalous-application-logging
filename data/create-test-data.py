import os
import random

def merge_files_keep_format(folder_paths, output_file, history_file):
    
    # Chuyển đổi đường dẫn tuyệt đối
    abs_output_file = os.path.abspath(output_file)
    abs_history_file = os.path.abspath(history_file)

    # 1. Đọc lịch sử
    processed_files = set()
    if os.path.exists(abs_history_file):
        with open(abs_history_file, 'r', encoding='utf-8') as f:
            processed_files = set(line.strip() for line in f)

    # 2. Tìm tất cả các file (Lấy đường dẫn tuyệt đối)
    files_to_process = []
    
    for folder in folder_paths:
        if not os.path.exists(folder):
            print(f"⚠️ Folder không tồn tại: {folder}")
            continue
            
        for root, dirs, files in os.walk(folder):
            for file in files:
                if file.endswith(".txt"):
                    full_abs_path = os.path.abspath(os.path.join(root, file))
                    
                    # Lọc file trùng
                    if (full_abs_path not in processed_files and 
                        full_abs_path != abs_output_file and 
                        full_abs_path != abs_history_file):
                        files_to_process.append(full_abs_path)

    if not files_to_process:
        print("🎉 Không có file mới nào cần xử lý.")
        return

    # 3. Random thứ tự FILE
    print(f"🔄 Đang trộn thứ tự {len(files_to_process)} file...")
    random.shuffle(files_to_process)

    # 4. Ghi file (Chế độ Copy-Paste nguyên khối)
    print(f"💾 Đang ghi vào {output_file}...")
    
    count = 0
    with open(abs_output_file, 'a', encoding='utf-8') as f_out:
        for file_path in files_to_process:
            try:
                content = ""
                # Đọc toàn bộ nội dung file vào biến (Read All)
                # Cách này giữ nguyên mọi dấu enter, tab trong văn bản
                try:
                    with open(file_path, 'r', encoding='utf-8') as f_in:
                        content = f_in.read()
                except UnicodeDecodeError:
                    with open(file_path, 'r', encoding='latin-1') as f_in:
                        content = f_in.read()

                # --- XỬ LÝ ĐIỂM NỐI ---
                # rstrip() chỉ cắt khoảng trắng/enter ở TẬN CÙNG file
                # Giữ nguyên cấu trúc bên trong đoạn văn
                content = content.rstrip()

                if content:
                    f_out.write(content)
                    
                    # Thêm 2 dấu xuống dòng: 
                    # 1 dấu để xuống dòng
                    # 1 dấu để tạo ra 1 dòng trống ngăn cách
                    f_out.write('\n\n')
                    
                    count += 1
                    print(f"✅ Đã chép: {os.path.basename(file_path)}")

                # Cập nhật lịch sử
                with open(abs_history_file, 'a', encoding='utf-8') as f_log:
                    f_log.write(file_path + '\n')

            except Exception as e:
                print(f"❌ Lỗi file {os.path.basename(file_path)}: {e}")

    print(f"✅ Hoàn tất! Đã nối {count} file.")

# --- CẤU HÌNH ---
if __name__ == "__main__":
    folder_a = r"E:\ProjectDev\detect-anomaly-logging\detect-anomalous-application-logging\output_logs\csic_2010"
    folder_b = r"E:\ProjectDev\detect-anomaly-logging\detect-anomalous-application-logging\output_logs\csic_2010_anomalous"
    
    output = "merged_output.txt"
    log = "processed_history.log"
    
    # Xóa log cũ để test lại từ đầu (nếu cần)
    if os.path.exists(log): os.remove(log)
    if os.path.exists(output): os.remove(output)

    merge_files_keep_format([folder_a, folder_b], output, log)