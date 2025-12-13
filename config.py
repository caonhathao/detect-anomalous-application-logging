from pathlib import Path
from dotenv import load_dotenv
import os

# Tự động tìm root
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')

MODEL_PATH = BASE_DIR / os.getenv("MODEL_FILENAME", "model.gguf")