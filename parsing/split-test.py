import os
import re

import os
import re

def split_log_file(input_path, output_folder, target_size_kb=5):
    """
    Tách file log lớn thành các file nhỏ dựa trên cấu trúc request đã gán nhãn dạng:
        SAFE|
        POST http...
        headers...
        
        MALICIOUS|
        GET http...
        headers...
    """

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Pattern nhận diện NHÃN (không phải request-line)
    label_pattern = re.compile(r'^(SAFE|MALICIOUS)\|$', re.IGNORECASE)

    current_chunk_content = []
    current_chunk_size = 0
    file_count = 1
    target_bytes = target_size_kb * 1024

    print("Đang xử lý...")

    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        current_block = []

        for line in f:
            # Nếu gặp dòng nhãn → bắt đầu request mới
            if label_pattern.match(line.strip()):
                # Nếu block cũ chưa ghi → thêm vào chunk
                if current_block:
                    block_text = "".join(current_block)
                    block_size = len(block_text.encode("utf-8"))

                    # Nếu vượt ngưỡng → ghi file mới
                    if current_chunk_size + block_size > target_bytes and current_chunk_size > 0:
                        _write_chunk(output_folder, file_count, current_chunk_content)
                        file_count += 1
                        current_chunk_content = []
                        current_chunk_size = 0

                    current_chunk_content.append(block_text)
                    current_chunk_size += block_size

                    current_block = []

            # Luôn thêm dòng vào block hiện tại
            current_block.append(line)

        # Block cuối
        if current_block:
            block_text = "".join(current_block)
            current_chunk_content.append(block_text)

        # Ghi chunk cuối
        if current_chunk_content:
            _write_chunk(output_folder, file_count, current_chunk_content)

    print(f"Hoàn tất! Đã tách thành {file_count} file trong thư mục '{output_folder}'.")


def _write_chunk(folder, count, content_list):
    filename = os.path.join(folder, f"log_part_{count:04d}.txt")
    with open(filename, 'w', encoding='utf-8') as out:
        out.write("".join(content_list))


# --- CONFIG ---
if __name__ == "__main__":
    FILE_LOG_GOC = "merged_output.txt"  # file đã merge + gán nhãn
    THU_MUC_OUT = "csic_2010_test"

    split_log_file(FILE_LOG_GOC, THU_MUC_OUT, target_size_kb=6)
