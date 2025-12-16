import re
from demo.drain3_instance import drain3_instance


def parsing_http_requests(file):
    req_lines = []
    content_len = None
    body_read = 0

    for line in file:
        line = line.rstrip("\n")

        if content_len is not None:
            req_lines.append(line)
            body_read += len(line.encode())

            if body_read >= content_len:
                yield " ".join(req_lines)
                req_lines = []
                content_len = None
                body_read = 0
            continue

        if line == "":
            if not req_lines:
                continue
            req_lines.append("")
            for h in req_lines:
                if h.lower().startswith("content-length"):
                    try:
                        content_len = int(h.split(":")[1].strip())
                    except ValueError:
                        pass
                    break

            if content_len is None:
                yield " ".join(req_lines)
                req_lines = []
            continue

        if line.strip() == "null":
            continue

        req_lines.append(line)

    if req_lines:
        full_log = " ".join(req_lines).strip()
        if full_log:  # Chỉ yield nếu có nội dung
            yield " ".join(req_lines)

def process_log_string(log_string):
    try:
        log_line = drain3_instance.add_log_message(log_string)
        template_str = log_line.get("template_mined")
        return {
            "Original Content": log_string,
            "EventId": log_line.get("cluster_id"),
            "EventTemplate": template_str,
        }
    except Exception as e:
        print(f"Lỗi khi xử lý log: {e}")
        return log_string, {}


def extract_label(log_string):
    label = 0
    if "class: attack" in log_string.lower():
        label = 1
    elif "class: valid" in log_string.lower():
        label = 0

    clean_log = re.sub(r'class:\s*\w+', '', log_string, flags=re.IGNORECASE)
    clean_log = re.sub(r'\s+', ' ', clean_log).strip()

    return label, clean_log

