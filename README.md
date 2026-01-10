# Detect Anomalous Application Logging 🔍

**Detect Anomalous Application Logging** is a Python toolkit and demo suite for parsing HTTP/application logs, preparing labeled datasets (CSIC-2010 style), running template mining and LogBERT anomaly detection, and producing human-readable explanations using LLMs (Gemini or local GGUF models).

- Language: **Python 3.8+**
- Purpose: detect anomalous requests (SQLi/XSS/RCE/path traversal/etc.), provide risk scoring and LLM-backed explanations, and help build training datasets for model development.

---

## Table of contents

- [Introduction](#introduction)
- [Key features](#key-features)
- [Overall architecture](#overall-architecture)
- [Installation](#installation)
- [Running the project](#running-the-project)
- [Environment configuration](#environment-configuration)
- [Folder structure](#folder-structure)
- [Contribution guidelines](#contribution-guidelines)
- [License](#license)
- [Roadmap](#roadmap)

---

## Introduction

This repository bundles a reproducible pipeline for log-based anomaly detection: parsing & masking, template mining (Drain3), event-to-id sequence creation, LogBERT-style anomaly scoring, and LLM-based explanation. It is targeted at security engineers and ML practitioners who want an end-to-end, explainable log anomaly workflow for research or small-scale deployment.

---

## Key features ✅

- Log preprocessing and masking (CSIC-style) with chunking for downstream processing.
- Label and merge flows to create `merged_output.txt` containing `SAFE|` / `MALICIOUS|` labeled request blocks.
- Drain3 template mining to convert request text to templates and `EventId`.
- LogBERT-style masked-LM anomaly detection (`src/detector.py`) for scoring and detecting unusual events.
- LLM explainer (`src/explainer.py`) using **Gemini** (Google Generative API) or local LLMs via `llama_cpp` (GGUF) for contextual explanation of anomalies.
- Demo analyzer (`demo/v7_only_ai/analyzer.py`) that orchestrates processing, scoring, optional LLM calls, and writes outputs to `logs/`.
- Lightweight tools to create JSONL training parts (`data/prepare-data.py`) for model development.

---

## Technologies & Integrations 🧩

- **LLMs / explainers:** Google Generative (Gemini), `llama_cpp` (GGUF local models), and **KoboldCPP** (local LLM server / REST API).
- **Template mining:** Drain3
- **Anomaly detection:** LogBERT (PyTorch + Transformers)
- **Data & utilities:** pandas, regex, urllib, python-dotenv
- **Web/UI & tooling:** Streamlit, requests, websockets, tqdm

> Tip: To use a local LLM server such as KoboldCPP, ensure it exposes a REST endpoint and point `SERVICES` (or `KOBOLDCPP_URL`) in `.env` to the service URL(s) (e.g., `http://localhost:5001/api/v1/generate`).

---

## Overall Architecture 🔧

```mermaid
flowchart LR
  subgraph Ingest
    A[Raw Logs (CSIC/raw)] --> B[parsing/preprocess-log.py]
  end

  B --> C[Masked / Chunked output (output_logs/)]
  C --> D[data/create-test-data.py]
  D --> E[merged_output.txt]
  E --> F[parsing/split-test.py]
  F --> G[logs/csic_2010_test/*]

  G --> H[demo/v7_only_ai/analyzer.py]
  H --> I[Drain3 Template Miner (demo/drain3_instance.py)]
  H --> J[LogBERT Detector (src/detector.py)]
  H --> K[LLM Explainer (src/explainer.py or external services)]

  J --> L[Anomalies & Scores]
  K --> M[Human-readable Explanations]
  L & M --> N[logs/debug_logs/ and logs/logs_missed/]
```

> Data flows from raw logs to masked chunks, to labeled/merged files, then to test splits and the analyzer which fuses template mining, detection and explanation.

---

## Installation 🔧

1. Clone the repository:

```bash
git clone <repo-url>
cd detect-anomalous-application-logging
```

2. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\activate
pip install -r requirements.txt
```

3. Optional: install local LLM runtime (`llama_cpp`) when using GGUF models.

---

## Running the project ▶️

Below are the most common operations and examples collected from the repo.

1. Preprocess raw logs (masking & chunking):

```bash
python parsing/preprocess-log.py
```

2. Create labeled test dataset (`SAFE|` / `MALICIOUS|` blocks):

```bash
python data/create-test-data.py
```

3. Split merged file into test parts:

```bash
python parsing/split-test.py
```

4. Convert merged logs to JSONL training parts:

```bash
python data/prepare-data.py
```

5. Test Drain3 template miner (quick check):

```python
from demo.drain3_instance import drain3_instance
print(drain3_instance.add_log_message('GET /index HTTP/1.1'))
```

6. Run the main analyzer demo (end-to-end; uses `LOG_FOLDER` from `.env`):

```bash
python demo/v7_only_ai/analyzer.py
```

- The analyzer expects `LOG_FOLDER` to point at split test files (e.g., `logs/csic_2010_test`). It writes results and debug files into `logs/debug_logs/` and `logs/logs_missed/` (false negatives, false positives, unknowns).
  - To use **KoboldCPP** (or any local LLM server with a REST API) with the analyzer, run the service and set `SERVICES` (or `KOBOLDCPP_URL`) in your `.env` to its endpoint(s) (for example: `SERVICES=http://localhost:5001/api/v1/generate`). The analyzer will round-robin requests and automatically perform service health checks.

7. Streamlit explainer UI (legacy, optional):

```bash
streamlit run explain.py
```

8. GPU/local LLM model test:

```bash
python demo/test-gpu.py
```

9. Quick LogBERT example (from `src/detector.py`):

```python
from src.detector import LogBertAnalyzer
analyzer = LogBertAnalyzer(vocab_size=5000, max_len=5)
res = analyzer.detect_anomalies([10,12,13,999,14])
print(res)
```

---

## Environment configuration ⚙️

The project uses a `.env` file (loaded by `python-dotenv` in `config.py`) for runtime configuration and secrets. Example `.env`:

```text
LOG_FOLDER=logs/csic_2010_test
GOOGLE_API_KEY=your_gemini_api_key_here
MODEL_FILENAME=model.gguf
# Optional: external LLM services (comma separated)
# SERVICES=http://localhost:5001/api/v1/generate,http://localhost:5002/api/v1/generate
# Example: If you're running KoboldCPP (or another local LLM server) with a REST API, point SERVICES to its endpoint(s):
# SERVICES=http://localhost:5001/api/v1/generate
# Alternatively you can set a single variable for clarity:
# KOBOLDCPP_URL=http://localhost:5001/api/v1/generate

```

Key variables referenced by code:

- `LOG_FOLDER` — folder containing split test files; required by `demo/v7_only_ai/analyzer.py` (script will raise if unset).
- `GOOGLE_API_KEY` — used by `src/explainer.py` for Gemini.
- `MODEL_FILENAME` — used by `config.py` to locate local GGUF models (via `MODEL_PATH`).
- `models/saved_bert/logbert_trained.pth` — expected by `src/detector.py` (LogBERT weights).

> Note: `config.py` sets `MODEL_PATH = BASE_DIR / os.getenv('MODEL_FILENAME', 'model.gguf')`.

---

## Folder structure (concise) 📁

- `parsing/` — preprocessing and splitting utilities
- `data/` — dataset creation and JSONL conversion
- `demo/` — demo scripts and Drain3 init
- `demo/v7_only_ai/` — main analyzer (`analyzer.py`) and LLM demo helpers
- `src/` — core modules (`parser.py`, `detector.py`, `explainer.py`)
- `models/` — saved model weights and checkpoints
- `logs/` — test logs, debug outputs and missed detection logs
- `output_logs/` — masked/chunked outputs from preprocessing
- `training_data/` — generated JSONL parts for training

---

## Contributing guidelines 🤝

We welcome contributions. Keep changes focused, well-tested, and documented.

- Open an issue first to discuss larger changes.
- Fork the repo and create a branch: `feature/<short-description>` or `fix/<short-desc>`.
- Add tests where possible and run them locally.
- Follow Python best practices (PEP8). Use `black`/`flake8` if added later.
- Write clear commit messages and a descriptive PR title + body. Link the issue in your PR.

Optional PR checklist (suggested):

- [ ] Code is formatted and linted
- [ ] Tests added/updated or manual steps documented
- [ ] README updated if behavior changed
- [ ] `.env`-safe (no keys committed)

---

## License ⚖️

I did not find a `LICENSE` file in the repository. Please add one to declare terms clearly. Common options:

- **MIT** — permissive and commonly used for open source.
- **Apache-2.0** — permissive + patent grant.

If you want, I can add an `MIT` `LICENSE` file and update this section accordingly.

---

## Roadmap 🛣️

Planned / suggested improvements:

1. Add a unit/integration test suite and CI (GitHub Actions).
2. Package the pipeline into a Docker image for reproducible runs.
3. Improve `app.py` into a small CLI wrapper with subcommands (preprocess, create, analyze, explain).
4. Add automated dataset validation and `train`/`eval` scripts with example configs.
5. Add an optional web UI (modern replacement for the legacy Streamlit explainer).
6. Add pre-commit hooks and linting config.

---

## Support & Contact

If you find bugs or want enhancements: open an issue. For quick help, annotate the issue with relevant logs and a short reproduction.



