from llama_cpp import Llama
from dotenv import load_dotenv
import os
from config import MODEL_PATH

load_dotenv()

print("Test loading model...")
llm = Llama(
    model_path=MODEL_PATH,
    n_gpu_layers=-1, # Đẩy hết lên GPU
    verbose=True     # BẬT verbose để xem log nạp
)

# Gửi 1 prompt test
output = llm("Hello AI", max_tokens=10)
print("Done.")