import os
import re

def split_log_file(input_path, output_folder, target_size_kb=5):
    """
    Tách file log lớn thành các file nhỏ dựa trên cấu trúc HTTP Request.
    
    Args:
        input_path: Đường dẫn file log gốc.
        output_folder: Thư mục chứa các file đầu ra.
        target_size_kb: Dung lượng mục tiêu mỗi file (KB). 
                        File có thể lớn hơn một chút để không cắt ngang log.
    """
    
    # Tạo thư mục đầu ra nếu chưa có
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Regex nhận diện dòng bắt đầu của 1 Request (Dựa trên CSIC 2010)
    # Tìm các dòng bắt đầu bằng GET, POST, PUT, v.v... theo sau là http
    log_start_pattern = re.compile(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+http', re.IGNORECASE)

    current_chunk_content = []
    current_chunk_size = 0
    file_count = 1
    
    # Ngưỡng byte (KB * 1024)
    target_bytes = target_size_kb * 1024

    print("Đang xử lý...")

    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        # Biến lưu trữ log hiện tại đang đọc dở
        current_log_buffer = []
        
        for line in f:
            # Kiểm tra xem dòng này có phải là bắt đầu của 1 log mới không
            if log_start_pattern.match(line):
                # Nếu đã có log trong buffer (tức là đã đọc xong log trước đó)
                if current_log_buffer:
                    log_str = "".join(current_log_buffer)
                    log_size = len(log_str.encode('utf-8'))
                    
                    # Kiểm tra: Nếu thêm log này vào mà vượt quá size mục tiêu -> Ghi file cũ, sang file mới
                    if current_chunk_size + log_size > target_bytes and current_chunk_size > 0:
                        _write_chunk(output_folder, file_count, current_chunk_content)
                        file_count += 1
                        current_chunk_content = []
                        current_chunk_size = 0
                    
                    # Thêm log vừa đọc xong vào chunk hiện tại
                    current_chunk_content.append(log_str)
                    current_chunk_size += log_size
                    
                    # Reset buffer cho log mới
                    current_log_buffer = []

            # Thêm dòng hiện tại vào buffer
            current_log_buffer.append(line)

        # Xử lý log cuối cùng còn sót lại trong buffer
        if current_log_buffer:
            log_str = "".join(current_log_buffer)
            current_chunk_content.append(log_str)

        # Ghi chunk cuối cùng ra file
        if current_chunk_content:
            _write_chunk(output_folder, file_count, current_chunk_content)

    print(f"Hoàn tất! Đã tách thành {file_count} file trong thư mục '{output_folder}'.")

def _write_chunk(folder, count, content_list):
    filename = os.path.join(folder, f"log_part_{count:04d}.txt")
    with open(filename, 'w', encoding='utf-8') as out:
        out.write("".join(content_list))
    # print(f"Đã ghi: {filename}")

# --- CẤU HÌNH SỬ DỤNG ---
if __name__ == "__main__":
    # Thay đổi tên file của bạn ở đây
    FILE_LOG_GOC = "E:\\ProjectDev\\detect-anomaly-logging\\detect-anomalous-application-logging\\data\\merged_output.txt"
    THU_MUC_OUT = "E:\\ProjectDev\\detect-anomaly-logging\\detect-anomalous-application-logging\\data\\csic_2010_test"
    
    # Vì bạn muốn 4-8KB, tôi để target là 6KB. 
    # Code sẽ gom log cho đến khi vượt 6KB thì ngắt sang file mới.
    split_log_file(FILE_LOG_GOC, THU_MUC_OUT, target_size_kb=6)