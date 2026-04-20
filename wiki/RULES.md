# Rules – Extracted from T&Cs

## Scoring Formula
- **F1 Score** = `2 * Precision * Recall / (Precision + Recall)`
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)

## Error Asymmetry
- **False Positive** = unnecessary activation → wastes resources, reduces system credibility
- **False Negative** = missed prevention → missed early optimization, worse long-term health

## Additional Metrics (Cost/Speed/Efficiency)
- Reward optimized agent architecture
- Detect clinical needs in real time with low operational expense
- Balance computational resources, latency, infrastructure usage
- Measure scalability, responsiveness, economic sustainability

## Constraints
- T > 0 (at least one citizen)
- T ∈ ℝ

## Submission Rules
- Training datasets: multiple submissions allowed, max score kept
- Evaluation datasets: **ONLY FIRST submission accepted**, considered final
- Need 3 elements: Langfuse Session ID, output .txt files, source code .zip
- Output must be UTF-8 plain text

## Anti-patterns (avoid)
- Static predictive approaches (must be adaptive)
- Over-reliance on LLM for everything (cost penalty)
- Ignoring temporal evolution of patterns
