# Reply Mirror Challenge 2026 - Fraud Detection ("The Eye")
## Team: Dogtors

### Architecture
- **Python feature engineering** (phishing detection, baselines, impossible travel)
- **LLM agents** (GPT-4o per-citizen analysis, Gemini 2.0 Flash audio transcription)
- **Parallel execution** via ThreadPoolExecutor for speed
- **Langfuse tracing** for observability and scoring

### Setup
```bash
pip install -r requirements.txt
```

### Configuration
Copy `.env.example` to `.env` and fill in your API keys:
- `OPENROUTER_API_KEY` - OpenRouter API key (for LLM calls)
- `LANGFUSE_PUBLIC_KEY` - Langfuse public key
- `LANGFUSE_SECRET_KEY` - Langfuse secret key
- `LANGFUSE_HOST` - Langfuse host URL
- `TEAM_NAME` - Team name

### Run
```bash
# Set the level directories in main() then:
PYTHONUNBUFFERED=1 python3 main.py
```

### Output
- `blade_runner.txt` - Fraudulent transaction IDs for Level 4
- Each file contains one UUID per line (fraudulent transaction IDs only)

### Level Data
Place level data folders at the same level as `outputs/`, e.g.:
```
Reply/
├── Blade Runner - validation/
│   ├── transactions.csv
│   ├── users.json
│   ├── locations.json
│   ├── sms.json
│   ├── mails.json
│   └── audio/
└── outputs/
    ├── main.py
    ├── .env
    └── blade_runner.txt
```

### Models Used
- `openai/gpt-4o` - Per-citizen fraud analysis
- `google/gemini-2.0-flash-001` - Audio transcription
