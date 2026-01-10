# Detect Anomalous Application Logging 🔍

**Detect Anomalous Application Logging** is a Python project for parsing HTTP/application logs, preparing datasets, running anomaly detection, and generating human-readable explanations for anomalies (LLM-backed). The repository contains utilities to preprocess log files (CSIC-2010 style), label/merge them, build training JSONL, run template mining with Drain3, run a LogBERT-based detector, and interactively inspect logs with an LLM explainer.

---

## Table of contents

- Quick start
- Detailed features & file map
- How to run demos
- Data pipeline (preprocess → label → split → create training)
- Detection & explanation examples
- Troubleshooting & environment

---

## Quick start ⚡

Prerequisites:

- Python 3.8+ (recommended)
- Create/activate a virtual environment

Install dependencies:

```bash
python -m venv .venv
.\.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

Common tasks:

- Preprocess raw CSIC logs: `python parsing/preprocess-log.py`
- Create labeled/merged dataset: `python data/create-test-data.py`
- Convert merged logs into training JSONL: `python data/prepare-data.py`
- Run the Streamlit explainer UI: `streamlit run explain.py`
- Run GPU model test (LLM local model): `python demo/test-gpu.py`

---

## Detailed features & file map 🔧

Top-level files:

- `README.md` — this file
- `app.py` — placeholder for a unified CLI/runner (currently empty)
- `config.py` — central config (reads `.env`, used by demo scripts to find `MODEL_PATH`)
- `drain3.ini` — configuration for Drain3 TemplateMiner (used by `demo/drain3_instance.py`)
- `explain.py` — Streamlit UI to browse a folder of logs and call the LLM explainer (`LlmExplainer` in `src/explainer.py`)

Project structure (snapshot):

```
/ (repo root)
├─ README.md
├─ app.py
├─ config.py
├─ drain3.ini
├─ explain.py
├─ demo/
│  ├─ drain3_instance.py
│  └─ test-gpu.py
├─ data/
│  ├─ create-test-data.py
│  └─ prepare-data.py
├─ parsing/
│  ├─ preprocess-log.py
│  └─ split-test.py
├─ src/
│  ├─ parser.py
│  ├─ detector.py
│  └─ explainer.py
├─ logs/              # raw logs and categorized sets
├─ output_logs/       # processed and chunked outputs
├─ training_data/     # JSONL training parts
└─ models/            # saved model weights
```

Quick map of important scripts and their purpose:

- `parsing/preprocess-log.py` — clean and mask raw logs; chunk outputs to `output_logs/`.
- `data/create-test-data.py` — label blocks (SAFE| / MALICIOUS|), merge labeled files into `merged_output.txt`.
- `parsing/split-test.py` — split `merged_output.txt` into smaller files for testing/evaluation.
- `data/prepare-data.py` — create training JSONL parts from merged inputs and apply safe masking.
- `demo/drain3_instance.py` — initializes Drain3; used to mine templates and generate `EventId`/`EventTemplate`.
- `src/detector.py` — load LogBERT and detect anomalies in sequences of event ids.
- `explain.py` + `src/explainer.py` — Streamlit UI + LLM wrapper (Gemini) to analyze and explain suspicious logs.

---

## Technologies used 🛠️

This project uses the following technologies and libraries:

- **Language & runtime:** Python 3.8+
- **Deep learning / LLMs:** PyTorch, Hugging Face Transformers, Masked LM (BERT) models
- **Detection model:** LogBERT-style masked-LM (custom weights in `models/saved_bert/`)
- **Template mining / log parsing:** Drain3 (via `demo/drain3_instance.py`)
- **LLM explainers / local LLMs:** `google.generativeai` (Gemini) and `llama_cpp` for local GGUF models
- **Data processing & utilities:** pandas, regex, urllib, python-dotenv
- **Web/UI:** Streamlit (legacy explainer UI)
- **Networking & services:** requests, websockets
- **Dev tooling:** tqdm, matplotlib for plotting and simple analysis

---

## Steps to prepare data, run tests & demos ▶️

Follow these steps for a complete local flow (prepare data → train/test → demo):

1. Prepare raw input files
   - Place CSIC-2010 raw files (or your logs) into `output_logs/_csic_2010_raw/` or change `INPUT_FOLDER` at the top of `parsing/preprocess-log.py`.

2. Preprocess & chunk logs
   - Run: `python parsing/preprocess-log.py`
   - Outcome: cleaned and masked files written to `output_logs/csic_2010_masking_anomalous` (or configured output).

3. Create labeled test dataset
   - Edit the folder constants in `data/create-test-data.py` to point to your normal/attack folders.
   - Run: `python data/create-test-data.py`
   - Outcome: `merged_output.txt` with `SAFE|` / `MALICIOUS|` labeled blocks.

4. Split merged file for testing
   - Run: `python parsing/split-test.py`
   - Outcome: many smaller `csic_2010_test/log_part_****.txt` files ready for evaluation.

5. Convert to training JSONL (optional — for LLM training)
   - Run: `python data/prepare-data.py`
   - Outcome: `training_data/train_part_*.jsonl` files (for model training / finetuning).

6. Test Drain3 template mining (optional but recommended)
   - Quick check in Python REPL:

```python
from demo.drain3_instance import drain3_instance
print(drain3_instance.add_log_message('GET /index HTTP/1.1'))
```

7. Run the Streamlit explainer UI
   - Set `GOOGLE_API_KEY` in `.env` if you plan to use Gemini via `src/explainer.py`.
   - Edit the `FOLDER` path in `explain.py` to point to your folder of logs (e.g., `logs/malicious_requests.txt` or an output folder).
   - Run: `streamlit run explain.py`

8. Test local LLM GPU loading (LLM demo)
   - Put local model file name into `.env` as `MODEL_FILENAME` or set `MODEL_PATH` in `config.py`.
   - Run: `python demo/test-gpu.py`

9. Run anomaly detection example (LogBERT)
   - Example snippet (Python):

```python
from src.detector import LogBertAnalyzer
analyzer = LogBertAnalyzer(vocab_size=5000, max_len=5)
res = analyzer.detect_anomalies([10, 12, 13, 999, 14])
print(res)
```

---

Notes & tips:

- Many scripts define folder paths / constants at the top — update them for Windows absolute paths if needed.
- Secrets (API keys, model filenames) should go into `.env` in the repo root.
- If you want, I can add a small `Makefile`/PowerShell script with these commands or turn `app.py` into a simple CLI to run the pipeline with consistent flags.


---

## How to run demos and common flows ▶️

1) Explainer UI (deprecated)

- Note: The Streamlit-based `explain.py` is present but is no longer the recommended workflow and may be unmaintained. Prefer the main analyzer demo (`demo/v7_only_ai/analyzer.py`), which provides integrated processing and LLM explanation options.
- If you still want to use `explain.py`: ensure `GOOGLE_API_KEY` is set in `.env`, edit the `FOLDER` variable at the top of `explain.py` to point to your logs, and then run:

```bash
streamlit run explain.py
```

- Recommendation: use `.env` files for configuration rather than setting temporary environment variables in your shell.

2) Test local LLM GPU loading

- Purpose: quick test that your local LLM model (e.g., GGUF) is loadable via `llama_cpp`.
- Configure `MODEL_FILENAME` in `.env` or edit `config.py`.
- Run:

```bash
python demo/test-gpu.py
```

3) Main analyzer demo (runanalyzer.py)

- Purpose: run the end-to-end analyzer/demo which reads labeled test files, processes requests, runs template mining, scoring and optional LLM explanation. This is the main demo you mentioned.
- Data used: set `LOG_FOLDER` to `logs/csic_2010_test` (this folder contains the split `log_part_*.txt` files created by `parsing/split-test.py`).
- Configure using a `.env` file (preferred) at the repo root. Example:

```
LOG_FOLDER=logs/csic_2010_test
```

Then run:

```bash
python demo/v7_only_ai/analyzer.py
```

- Notes & behavior:
  - The demo reads files from `LOG_FOLDER`, applies parsing/masking, calls the configured services / local LLMs, and writes outputs and debug files to `logs/debug_logs/` and `logs/logs_missed/` (`false_negative.txt`, `false_positive.txt`, `unknown.txt`).
  - To stop the demo, press Ctrl+C. Configure constants inside `demo/v7_only_ai/analyzer.py` (e.g., `SERVICES`, `WORKER_COUNT`, `REQUEST_TIMEOUT`) to match your environment.
  - Avoid relying on ad-hoc PowerShell environment settings for persistent runs; prefer `.env` for reproducibility.

4) Drain3 template mining

- `demo/drain3_instance.py` exposes `drain3_instance` configured from `drain3.ini`.
- Example usage: `from demo.drain3_instance import drain3_instance` then `drain3_instance.add_log_message(text)` to get `cluster_id` and `template_mined`.

4) Detection using `LogBertAnalyzer`

- Minimal example:

```python
from src.detector import LogBertAnalyzer

analyzer = LogBertAnalyzer(vocab_size=5000, max_len=5)
event_ids = [10, 12, 13, 999, 14]  # example sequence of event/template ids
res = analyzer.detect_anomalies(event_ids, top_k=20, confidence_threshold=0.01)
print(res)
```

- Output: dictionary with `total_logs`, `total_windows`, `anomaly_count`, and `anomalies` (items show `LineId`, `EventId`, `Confidence`).

---

## Data pipeline (recommended order)

1. Place raw CSIC (or other) logs in `output_logs/_csic_2010_raw/` or adjust `INPUT_FOLDER` in scripts.
2. Run `python parsing/preprocess-log.py` to clean and mask sensitive fields and chunk files.
3. Use `python data/create-test-data.py` to generate labeled files and `merged_output.txt` (edit the paths at the top of that script to match your local layout).
4. Run `python parsing/split-test.py` to split the merged labeled file into smaller test files.
5. Create LLM training JSONL parts with `python data/prepare-data.py`.

---

## Environment variables & .env structure ⚠️

- Use a `.env` file at the repo root to set configuration and secrets (preferred over setting temporary env vars in PowerShell).

- Minimal `.env` example (edit as needed):

```
# Where the analyzer reads test files
LOG_FOLDER=logs/csic_2010_test

# Google Generative (Gemini) API key (optional, for LLM explain)
GOOGLE_API_KEY=your_gemini_api_key_here

# Local LLM model filename (used by demo/test-gpu.py via config.py)
MODEL_FILENAME=model.gguf

# Optional: comma-separated service endpoints used by analyzer (overrides default in analyzer.py)
# SERVICES=http://localhost:5001/api/v1/generate,http://localhost:5002/api/v1/generate
```

- Notes:
  - The project uses `python-dotenv` to load `.env` values in `config.py` and many demo scripts.
  - After editing `.env` you can run scripts directly: `python demo/v7_only_ai/analyzer.py` (no need to set PowerShell environment variables manually).
  - `models/saved_bert/logbert_trained.pth` is expected by `src/detector.py`. If you don't have it, `LogBertAnalyzer` will fail to load state.

- Many helpers include configurable folder paths at the top — update them for Windows absolute paths when necessary.

---

## Troubleshooting & tips 💡

- If `streamlit run explain.py` shows an empty folder, set `FOLDER` correctly or export an env var and modify `explain.py` to read it.
- If `demo/test-gpu.py` fails to load your model, check `MODEL_FILENAME` and installed `llama_cpp` compatibility.
- When preparing training data, ensure the raw input files are in the expected format (CSIC-style) or adjust regex in `data/prepare-data.py`.

---

## Contributing & License 🤝

Contributions are welcome — open issues or submit PRs.
