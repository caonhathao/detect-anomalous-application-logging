import streamlit as st
import os

from src.explainer import LlmExplainer
from streamlit_autorefresh import (
    st_autorefresh,
)  # pip install streamlit-autorefresh nếu chưa có

FOLDER = "logs/malicious"

st.title("🔎 Xem & phân tích log malicious")

# 1. Tự động check xem folder đã tồn tại chưa
if not os.path.exists(FOLDER):
    st.info(f"⏳ Đang chờ thư mục log xuất hiện: `{FOLDER}`")

    # Tự động reload sau mỗi 3 giây, không spam log
    st_autorefresh(interval=3000, key="wait_for_folder")
    st.stop()  # Dừng hẳn việc chạy phần code phía dưới

# 2. Folder đã tồn tại => chạy bình thường từ đây trở xuống
llm = LlmExplainer()
all_files = os.listdir(FOLDER)

if not all_files:
    st.warning("📂 Thư mục đã tồn tại nhưng chưa có file log nào.")
    # Có thể auto-refresh tiếp để chờ file mới
    st_autorefresh(interval=3000, key="wait_for_files")
    st.stop()

# 3. Tìm kiếm file theo keyword
keyword = st.text_input("🔍 Tìm file (gõ một phần tên)")

filtered_files = (
    [f for f in all_files if keyword.lower() in f.lower()] if keyword else all_files
)

if not filtered_files:
    st.warning("❌ Không tìm thấy file nào khớp với từ khóa.")
    st.stop()

# 4. Chọn file & hiển thị nội dung
selected_file = st.selectbox("Chọn file log", filtered_files[:100])

st.write(f"Đang hiển thị nội dung của file: **{selected_file}**")

content = ""
if selected_file:
    file_path = os.path.join(FOLDER, selected_file)
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    st.text_area("Nội dung file log", content, height=400)

# 5. Gọi LLM phân tích
st.markdown("### 🤖 Gemini phân tích:")
if st.button("Phân tích"):
    if not content.strip():
        st.warning("File trống, không có gì để phân tích.")
    else:
        st.write("Đang phân tích...")
        with st.spinner("Gemini đang đọc log và suy luận... vui lòng chờ..."):
            explanation = llm.explain_anomaly(content)
            st.write(explanation)
