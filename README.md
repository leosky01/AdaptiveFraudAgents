# AdaptiveFraudAgents

Solution for the **Reply Mirror 2026 "The Eye"** challenge — a fraud detection competition by [Reply](https://challenges.reply.com).

## The Challenge

Detect **fraudulent financial transactions** in a simulated digital metropolis set in the year 2087. The system must analyze multi-source data to identify which transactions are fraud, outputting one fraudulent Transaction ID per line.

5 levels with increasing complexity. Scoring based on **Accuracy** (primary) and **Cost/Speed/Efficiency** (secondary).

### Data Sources
- **transactions.csv** — Financial transactions (transfers, e-commerce, in-person payments, etc.)
- **users.json** — Citizen profiles with demographic info and behavioral descriptions
- **locations.json** — GPS pings from citizen bio-tags
- **sms.json** — SMS messages (mix of legitimate and phishing)
- **mails.json** — Email threads (mix of legitimate and phishing)
- **audio/** — Phone call recordings (MP3) requiring transcription

## Architecture

### Python Feature Engineering
- **Phishing detection** from SMS/emails via typo-domain patterns (`paypa1`, `amaz0n`, `ub3r`, etc.)
- **Phishing susceptibility** extraction from user behavioral descriptions
- **Transaction baseline building** per citizen (recipients, amounts, timing patterns)
- **Impossible travel detection** comparing GPS pings vs in-person payment locations
- **Temporal correlation** between phishing events and suspicious transactions

### LLM Agents
- Per-citizen fraud analysis using **GPT-4o** via OpenRouter
- Audio transcription using **Gemini 2.0 Flash**
- LangChain + Langfuse for tracing and observability

## Dataset Included

This repo contains **only the "Blade Runner" level** (level 4) out of 5 challenge levels:
- `Data/Blade Runner - train/` — Training dataset with 72 audio files
- `Data/Blade Runner - validation/` — Validation dataset with 82 audio files

The other levels (The Truman Show, Brave New World, Deus Ex, etc.) are not included.

## Project Structure

```
.
├── outputs/
│   ├── main.py              # Main fraud detection pipeline (1091 lines)
│   ├── blade_runner.txt     # Output: fraudulent transaction IDs
│   ├── requirements.txt     # Python dependencies
│   ├── .env.example         # API key template
│   └── README.md            # Setup & run instructions
├── wiki/
│   ├── RULES.md             # Scoring rules and constraints
│   └── DATA.md              # Data schema documentation
├── Data/
│   ├── Blade Runner - train/    # Training data (transactions, users, SMS, mail, GPS, audio)
│   └── Blade Runner - validation/ # Validation data
```

## Quick Start

```bash
pip install -r outputs/requirements.txt
cp outputs/.env.example outputs/.env  # Fill in your API keys
PYTHONUNBUFFERED=1 python3 outputs/main.py
```

## Team

**Dogtors** — Reply Challenge 2026
