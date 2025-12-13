import re
import sys
from urllib.parse import unquote
from collections import Counter

def analyze_large_log(file_path, top_n=20):
    """
    Phân tích log file lớn theo dòng để tiết kiệm RAM.
    """
    # Counter chỉ lưu danh sách các token duy nhất và số lượng, 
    # tốn rất ít RAM so với việc lưu nội dung file.
    token_counter = Counter()
    
    # Regex pattern:
    # 1. [a-z0-9]{4,}: Bắt từ khóa dài hơn 4 ký tự (vd: select, union, passwd)
    # 2. [^a-z0-9\s]{2,}: Bắt ký tự đặc biệt liền kề (vd: ../, --, <!, ::)
    pattern = re.compile(r"([a-z0-9]{4,}|[^a-z0-9\s]{2,})")
    
    # Danh sách loại trừ (tiếng ồn)
    ignore_list = {
        'http', 'https', 'html', 'mozilla', 'chrome', 'safari', 
        'image', 'jpeg', 'woff', 'access', 'logs', 'android'
    }

    try:
        # errors='replace' giúp script không bị crash nếu log có ký tự nhị phân lạ
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            print(f"[*] Đang phân tích file: {file_path} ...")
            
            line_count = 0
            for line in f:
                line_count += 1
                
                # [Tùy chọn] Lọc nhanh: Chỉ phân tích các dòng có vẻ nguy hiểm
                # Nếu bạn muốn phân tích tất cả, hãy comment dòng if này lại.
                # if "404" not in line and "500" not in line: continue

                # 1. Giải mã URL (quan trọng cho log tấn công)
                decoded_line = unquote(line).lower()
                
                # 2. Tìm token
                tokens = pattern.findall(decoded_line)
                
                # 3. Lọc rác và đếm
                valid_tokens = [t for t in tokens if t not in ignore_list]
                token_counter.update(valid_tokens)

                # In tiến độ mỗi 50,000 dòng
                if line_count % 50000 == 0:
                    print(f"    -> Đã xử lý {line_count} dòng...", end='\r')

        print(f"\n[+] Hoàn tất xử lý {line_count} dòng.")
        return token_counter.most_common(top_n)

    except FileNotFoundError:
        print("Error: Không tìm thấy file log.")
        return []

# --- CẤU HÌNH CHẠY ---
if __name__ == "__main__":
    # Thay 'access.log' bằng tên file log thật của bạn
    LOG_FILE = 'normalTrafficTest.txt' 
    
    # Tạo file giả lập nếu chưa có để test
    # (Bạn có thể xóa đoạn này khi chạy với file thật)
    with open(LOG_FILE, 'w') as f:
        f.write('/product?id=1 union select 1,2,3\n' * 50)
        f.write('/admin/login.php?user=admin\' --\n' * 30)
        f.write('/image.png HTTP/1.1\n' * 1000) # Noise

    # Chạy phân tích
    results = analyze_large_log(LOG_FILE)

    print(f"\n{'='*40}")
    print(f"TOP KEYWORDS/REGEX ĐẶC TRƯNG TÌM ĐƯỢC")
    print(f"{'='*40}")
    print(f"{'Keyword':<20} | {'Số lần xuất hiện'}")
    print(f"{'-'*40}")
    
    for token, count in results:
        print(f"{token:<20} | {count}")