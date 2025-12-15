import os
import google.generativeai as genai
from dotenv import load_dotenv
from google.generativeai import client

load_dotenv()

API_KEY = os.getenv("GOOGLE_API_KEY")

class LlmExplainer:
    def __init__(self, api_key=None):
        self.api_key = API_KEY
        genai.configure(api_key=self.api_key)
        self.model_name = genai.GenerativeModel('gemini-2.5-flash')

    def get_context_for_llm(self, anomaly_line_index, raw_logs, window=10):
        # Lưu ý: anomaly_line_index ở đây là số thứ tự dòng (bắt đầu từ 1)
        # Convert về index mảng (bắt đầu từ 0)
        idx_array = anomaly_line_index - 1
        start_idx = max(0, idx_array - window)
        end_idx = min(len(raw_logs), idx_array + window + 1)

        context_logs = raw_logs[start_idx: end_idx]
        formatted_context = []

        for i, line in enumerate(context_logs):
            curr_line_id = start_idx + i + 1
            prefix = ">>> [ANOMALY] " if curr_line_id == anomaly_line_index else "    "
            formatted_context.append(f"{prefix}Line {curr_line_id}: {line.strip()}")
        return "\n".join(formatted_context)

    def generate_prompt(self, context_str):
        return f"""
                Bạn là chuyên gia System Admin & Security. Hệ thống của tôi phát hiện các log bất thường.

                Dữ liệu Log Context:
                ---------------------
                {context_str}
                ---------------------

                Yêu cầu phân tích:
                1. Giải thích ngắn gọn tại sao dòng này đáng ngờ trong ngữ cảnh trên?
                2. Dự đoán nguyên nhân gốc rễ (Root Cause).
                3. Đưa ra 1 giải pháp khắc phục ngay lập tức.
                4. Phân tích các lỗi bất thng ường khác (nếu có) trong ngữ cảnh trên.
                5. Đưa ra các khuyến nghị để ngăn chặn sự cố tương tự trong tương lai.
                
                Trả lời bằng tiếng Việt.
                """

    def explain_anomaly(self, context_str):
        prompt = self.generate_prompt(context_str)
        try:
            response = self.model_name.generate_content(prompt)
            return response.text

        except Exception as e:
            return f"❌ Lỗi khi gọi Gemini API: {str(e)}"