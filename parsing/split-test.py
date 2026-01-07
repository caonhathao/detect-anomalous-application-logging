import os
import re


def split_log_file(input_path, output_folder, max_requests_per_file=100):
    """
    Tách file log lớn thành các file nhỏ.
    Mỗi file chứa tối đa `max_requests_per_file` request,
    dựa trên cấu trúc request đã gán nhãn:
        SAFE|
        POST ...
        headers...

        MALICIOUS|
        GET ...
        headers...
    """

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Pattern nhận diện dòng NHÃN
    label_pattern = re.compile(r"^(SAFE|MALICIOUS)\|$", re.IGNORECASE)

    current_chunk_content = []
    current_request_count = 0
    file_count = 1

    print("Đang xử lý...")

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        current_block = []

        for line in f:
            # Nếu gặp nhãn → bắt đầu request mới
            if label_pattern.match(line.strip()):
                if current_block:
                    # Hoàn tất 1 request
                    block_text = "".join(current_block)
                    current_chunk_content.append(block_text)
                    current_request_count += 1

                    # Nếu đủ số request → ghi file
                    if current_request_count >= max_requests_per_file:
                        _write_chunk(output_folder, file_count, current_chunk_content)
                        file_count += 1
                        current_chunk_content = []
                        current_request_count = 0

                    current_block = []

            # Thêm dòng vào request hiện tại
            current_block.append(line)

        # Xử lý block cuối cùng
        if current_block:
            current_chunk_content.append("".join(current_block))
            current_request_count += 1

        # Ghi file cuối nếu còn dữ liệu
        if current_chunk_content:
            _write_chunk(output_folder, file_count, current_chunk_content)

    print(f"Hoàn tất! Đã tách thành {file_count} file trong thư mục '{output_folder}'.")


def _write_chunk(folder, count, content_list):
    filename = os.path.join(folder, f"log_part_{count:04d}.txt")
    with open(filename, "w", encoding="utf-8") as out:
        out.write("".join(content_list))


# --- CONFIG ---
if __name__ == "__main__":
    FILE_LOG_GOC = "merged_output.txt"  # file log lớn đã gán nhãn
    THU_MUC_OUT = "csic_2010_test"

    split_log_file(FILE_LOG_GOC, THU_MUC_OUT, max_requests_per_file=100)
