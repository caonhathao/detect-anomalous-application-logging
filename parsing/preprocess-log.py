import os
import re
import urllib.parse

# --- CẤU HÌNH ---
INPUT_FOLDER = "output_logs/csic_2010_anomalous"       # Thư mục chứa các file log gốc cần xử lý
OUTPUT_FOLDER = "output_logs/csic_2010_masking_anomalous" # Thư mục sẽ chứa các file đã chia nhỏ và làm sạch
TARGET_SIZE_KB = 6              # Dung lượng mục tiêu mỗi file con (KB)

def preprocess_log(log_string):
    """
    Hàm thực hiện Tiền xử lý (Cleaning) và Masking (Che giấu thông tin)
    """
    try:
        # 1. URL Decode: Chuyển %20 -> space, %3C -> <, ...
        # Giúp model học được ký tự thật thay vì mã hex
        log_string = urllib.parse.unquote(log_string)
        
        # 2. Selective Masking (Masking chọn lọc)
        
        # Mask Session ID (Hex 32 ký tự) -> <UUID>
        # Regex này bắt chuỗi JSESSIONID= theo sau là 32 ký tự hex
        log_string = re.sub(r'(JSESSIONID=)[a-fA-F0-9]{32}', r'\1<UUID>', log_string)
        
        # Mask Localhost/IP và Port -> <HOST>
        # Xử lý trong URL (http://localhost:8080...)
        log_string = re.sub(r'http://[\w\-\.]+:\d+', 'http://<HOST>', log_string)
        # Xử lý trong Header (Host: localhost:8080)
        log_string = re.sub(r'Host:\s+[\w\-\.]+:\d+', 'Host: <HOST>', log_string)
        
        # Lưu ý: Các tham số tấn công (id=1 OR 1=1) vẫn được GIỮ NGUYÊN
        
        return log_string
    except Exception as e:
        print(f"Lỗi khi xử lý log: {e}")
        return log_string

def write_chunk(folder, count, content_list):
    """Ghi nội dung từ bộ nhớ ra file"""
    if not content_list:
        return
    
    filename = os.path.join(folder, f"processed_part_{count:04d}.txt")
    with open(filename, 'w', encoding='utf-8') as out:
        out.write("".join(content_list))

def process_logs_pipeline():
    # Tạo thư mục output nếu chưa có
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
        
    # Regex nhận diện dòng bắt đầu của 1 Request
    log_start_pattern = re.compile(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+http', re.IGNORECASE)

    current_chunk_content = []
    current_chunk_size = 0
    file_count = 1
    target_bytes = TARGET_SIZE_KB * 1024
    
    # Lấy danh sách tất cả file trong thư mục input
    input_files = [f for f in os.listdir(INPUT_FOLDER) if os.path.isfile(os.path.join(INPUT_FOLDER, f))]
    
    print(f"Tìm thấy {len(input_files)} file trong thư mục '{INPUT_FOLDER}'. Bắt đầu xử lý...")

    # Duyệt qua từng file trong thư mục input
    for file_name in input_files:
        file_path = os.path.join(INPUT_FOLDER, file_name)
        print(f" -> Đang đọc: {file_name}")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            current_log_buffer = []
            
            for line in f:
                # Nếu gặp dòng bắt đầu log mới -> Xử lý log cũ trong buffer
                if log_start_pattern.match(line):
                    if current_log_buffer:
                        # 1. Ghép dòng thành 1 log hoàn chỉnh
                        raw_log = "".join(current_log_buffer)
                        
                        # 2. Áp dụng Preprocessing & Masking
                        cleaned_log = preprocess_log(raw_log)
                        
                        # 3. Tính toán dung lượng
                        log_size = len(cleaned_log.encode('utf-8'))
                        
                        # 4. Kiểm tra xem có cần tách file không
                        if current_chunk_size + log_size > target_bytes and current_chunk_size > 0:
                            write_chunk(OUTPUT_FOLDER, file_count, current_chunk_content)
                            file_count += 1
                            current_chunk_content = []
                            current_chunk_size = 0
                        
                        # 5. Thêm log sạch vào chunk hiện tại
                        current_chunk_content.append(cleaned_log)
                        current_chunk_size += log_size
                        
                        # Reset buffer
                        current_log_buffer = []

                # Thêm dòng hiện tại vào buffer (đang đọc dở log)
                current_log_buffer.append(line)

            # Xử lý log cuối cùng của file hiện tại (nếu có)
            if current_log_buffer:
                raw_log = "".join(current_log_buffer)
                cleaned_log = preprocess_log(raw_log)
                log_size = len(cleaned_log.encode('utf-8'))
                
                if current_chunk_size + log_size > target_bytes and current_chunk_size > 0:
                    write_chunk(OUTPUT_FOLDER, file_count, current_chunk_content)
                    file_count += 1
                    current_chunk_content = []
                    current_chunk_size = 0
                
                current_chunk_content.append(cleaned_log)
                current_chunk_size += log_size

    # Ghi nốt chunk cuối cùng nếu còn dữ liệu
    if current_chunk_content:
        write_chunk(OUTPUT_FOLDER, file_count, current_chunk_content)

    print(f"\nHOÀN TẤT! Dữ liệu đã được làm sạch và chia thành {file_count} file tại '{OUTPUT_FOLDER}'.")

if __name__ == "__main__":
    # Đảm bảo bạn đã tạo thư mục raw_logs và bỏ file vào đó trước khi chạy
    if not os.path.exists(INPUT_FOLDER):
        os.makedirs(INPUT_FOLDER)
        print(f"Đã tạo thư mục '{INPUT_FOLDER}'. Hãy copy file log vào đó rồi chạy lại script.")
    else:
        process_logs_pipeline()