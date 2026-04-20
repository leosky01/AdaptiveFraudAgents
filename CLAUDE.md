# Reply Mirror 2026 – "The Eye" – Fraud Detection

## Context
Detect **fraudulent financial transactions** in the digital metropolis of Reply Mirror (year 2087).
5 levels with increasing complexity. Output: ASCII file with one fraudulent Transaction ID per line.

## Architecture
- **Python feature engineering** does 90% of the work (0 LLM cost):
  - Phishing detection from SMS/emails (typo-domains: paypa1, amaz0n, ub3r, etc.)
  - Phishing susceptibility extraction from user descriptions
  - Transaction baseline building (per-citizen: recipients, amounts, timing)
  - Impossible travel detection (GPS vs in-person payment locations)
  - Temporal correlation (phishing → fraud window)
- **LLM agents** only for borderline cases via LangChain + Langfuse
- **Audio transcription** for Deus Ex level (48 MP3 files)
- Scoring: Accuracy (primary) + Cost/Speed/Efficiency (secondary, tracked via Langfuse)

## Key Files
- `raw/` – Training datasets (The Truman Show, Brave New World, Deus Ex)
- `wiki/` – AI-maintained knowledge base
- `outputs/main.py` – Main fraud detection pipeline
- `outputs/` – ZIP THIS for evaluation submission

## Rules
- Read `wiki/RULES.md` for scoring rules and constraints
- Read `wiki/DATA.md` for data schema
- Read `wiki/LANGFUSE.md` for exact tracing pattern
- Training datasets: can submit multiple times
- **Evaluation datasets: ONLY FIRST submission counts** – be sure before submitting
- Output invalid if: 0 txns reported, ALL txns reported, or <15% fraud recall

## Submission Checklist
1. Generate Langfuse session ID: `{TEAM_NAME}-{ULID}`
2. Run pipeline → generate output .txt files
3. For evaluation: zip `outputs/` folder and upload with session ID
