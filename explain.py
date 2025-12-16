import streamlit as st
import os

from src.explainer import LlmExplainer

FOLDER = "data/csic_2010_anomalous"
llm = LlmExplainer()
all_files = os.listdir(FOLDER)

keyword = st.text_input("🔍 Tìm file (gõ một phần tên)")

filtered_files = [
    f for f in all_files
    if keyword.lower() in f.lower()
]

selected_file = st.selectbox(
    "Chọn file log",
    filtered_files[:100]
)

st.write(f"Đang hiển thị nội dung của file: **{selected_file}**")
if selected_file:
    file_path = os.path.join(FOLDER, selected_file)
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    st.text_area("Nội dung file log", content, height=400)

st.markdown("Gemini Phân tích:")
if st.button("Phân tích"):
    st.write("Đang phân tích...")
    with st.spinner('Gemini đang đọc log và suy luận... vui lòng chờ...'):
        explanation = llm.explain_anomaly(content)
        st.write(explanation)