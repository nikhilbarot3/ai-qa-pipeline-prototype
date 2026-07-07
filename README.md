# QA for an AI-Enabled Security Pipeline
### Prototype: Testing LLM Output Quality Across an Ingestion → Normalization → PromptOps → Validation Pipeline

---

## What This Is

This notebook builds and tests a 4-stage QA pipeline that mirrors the architecture of an AI-enabled security platform — specifically the kind of pipeline where raw network telemetry is ingested from multiple sources, normalized into a common schema, passed through an LLM for human-readable threat analysis (PromptOps), and then validated for correctness and faithfulness.

The focus is **not** on building a threat detection product. The focus is on **what it takes to QA one** — testing LLM-generated outputs, validating schema fidelity, catching hallucination, and finding bugs in the validation logic itself.

---

## Pipeline Stages

```
Raw NSL-KDD Data
      │
      ▼
┌─────────────┐
│  Ingestion  │  Load 125,973 rows, 41 features, 23 attack labels
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│  Normalization   │  Map fragmented feature groups into one common schema
│                  │  Simulates 3 vendor sources: Connection / Endpoint / Traffic
└──────┬───────────┘
       │
       ▼
┌─────────────┐
│  PromptOps  │  Gemini generates plain-English threat narrative per record
│             │  Ground truth withheld — model never sees the label
└──────┬──────┘
       │
       ▼
┌──────────────────────┐
│  Output Validation   │  3-layer validation:
│                      │  1. Hand-rolled directional accuracy check
│                      │  2. Manual faithfulness review (numbers vs source fields)
│                      │  3. DeepEval LLM-as-judge scoring
└──────────────────────┘
```

---

## Dataset

**NSL-KDD** — network intrusion detection benchmark, sourced directly via script (no manual upload needed).

| Stat | Value |
|------|-------|
| Total rows | 125,973 |
| Features | 41 raw connection-level fields |
| Raw attack labels | 23 (neptune, satan, smurf, ipsweep, etc.) |
| Standard categories | 4 (DoS, Probe, R2L, U2R) + normal |
| Class distribution | 91.9% normal / 6% suspicious / 2% malicious |

NSL-KDD was chosen specifically because its labels are trustworthy — unlike a synthetic Kaggle dataset evaluated first, where label distribution was found to be statistically independent of actual signal fields (e.g. 92% of rows using known attack tools like Nmap/SQLMap were still labeled "benign").

---

## Normalization: Simulating Fragmented Sources

NSL-KDD's 41 features are split into 3 logical groups to simulate the kind of multi-vendor ingestion a real security platform would face:

| Group | Simulates | Fields |
|-------|-----------|--------|
| Source A | Firewall / connection log | protocol, service, flag, bytes sent/received |
| Source B | Endpoint / host log | failed logins, root shell, compromise indicators |
| Source C | IDS / traffic stats | connection counts, error rates |

Each group is field-mapped into one standardized schema:

```python
{
  "conn_protocol": "tcp",
  "conn_service": "private",
  "conn_flag_status": "S0",
  "bytes_sent": 0,
  "bytes_received": 0,
  "auth_failed_logins": 0,
  "auth_logged_in": False,
  "host_compromise_indicators": 0,   # sum of num_compromised + root_shell + su_attempted
  "conn_count_same_host": 229,
  "conn_error_rate": 1.0,
  "dst_host_conn_count": 255,
  "dst_host_error_rate": 1.0,
}
```

> **Honest caveat:** This is a single-source dataset with feature groups simulated as separate sources. A real Cosmos-scale join across distinct vendor outputs — with different keys, timestamps, and formats — is a meaningfully harder problem than this prototype solves.

Each normalized record carries a `_source_row_index` for full data lineage — so any transformed record can be traced back to its exact raw row in the original dataset. This was added mid-build after finding that transformed records had no traceability back to source, a real data-lineage gap.

---

## PromptOps: LLM-Generated Threat Narratives

Normalized records are sent to **Gemini** (gemini-2.5-flash) with a prompt asking for a plain-English security verdict. Ground truth is explicitly withheld — the model only sees the normalized fields, never the label.

**Sample input → output:**

```
Input:
  conn_flag_status: S0
  bytes_sent: 0, bytes_received: 0
  conn_count_same_host: 229
  conn_error_rate: 1.0  (100%)
  conn_service: private

Ground truth (hidden from LLM): DoS

Gemini output:
  "This record looks highly suspicious. It details a high volume of connection
  attempts (229 from the same host, 255 to the destination) all resulting in an
  S0 flag, indicating failed connections with no data exchanged. The 100% error
  rate for these connections strongly suggests activities like port scanning or
  a denial-of-service attempt targeting the 'private' service."
```

Rate limiting: Gemini free tier allows 5 requests/minute. The pipeline paces calls at 13s intervals and retries on 429 with exponential backoff.

---

## Output Validation: 3-Layer Approach

### Layer 1 — Directional Accuracy (hand-rolled)

Checks whether the LLM's verdict (suspicious vs. not) matches the ground truth.

**Bug found and fixed mid-build:**

The first version used naive keyword matching — searching for `"suspicious"` anywhere in the narrative text. This caused 3 correct narratives containing the phrase *"does **not** appear suspicious"* to be misclassified as FALSE POSITIVES, reporting 12/15 accuracy when the true result was 15/15.

Fix: replaced keyword matching with verdict-phrase matching and explicit negation handling.

```python
# Before (buggy)
flagged = any(word in text for word in ["suspicious", "malicious", ...])

# After (fixed)
negative_phrases = ["does not appear suspicious", "not suspicious", ...]
positive_phrases = ["highly suspicious", "denial-of-service", ...]
# Checks for whole phrases, handles negation correctly
```

> **Why this matters:** a test suite that lies about passing is worse than no test suite — it gives false confidence.

### Layer 2 — Manual Faithfulness Review

For each narrative, every number is flagged with `>>>N<<<` markers and printed next to the raw record fields, so claims can be manually traced back to actual source data. Also handles rate-vs-percentage conversion (e.g. stored as `1.0`, described as `100%`).

**Sample output:**
```
Record [0]  ground truth = DoS  (source = df.loc[0])

RAW NORMALIZED RECORD:
   conn_count_same_host  = 229
   conn_error_rate       = 1.0  (as %: 100)
   dst_host_conn_count   = 255

NARRATIVE (numbers flagged):
   "...high volume of connection attempts (>>>229<<< from the same host,
   >>>255<<< to the destination)...>>>100<<<% error rate..."

✓ All numbers trace back to source fields
```

### Layer 3 — DeepEval LLM-as-Judge

Uses **DeepEval** with Gemini as the judge model, running three metrics:

| Metric | What it checks | Score |
|--------|---------------|-------|
| `FaithfulnessMetric` | Do narrative claims stay grounded in the input data? | **1.00 ✓** |
| `AnswerRelevancyMetric` | Does the narrative actually address what was asked? | **1.00 ✓** |
| `GEval` (custom) | Does the verdict correctly classify the threat category? | **1.00 ✓** |

**How DeepEval works internally:**

Unlike our hand-rolled checker (string matching), DeepEval uses an LLM-as-judge pattern:
1. **Call 1** — extract all factual claims from the narrative
2. **Call 2+** — verify each claim against the source data (one call per claim)
3. **Score** = `claims_supported / total_claims` (simple ratio, no ML)

This is why DeepEval makes 2–3 API calls per metric rather than one — and why it handles negation and unit conversion correctly where string matching fails.

> **Production note:** Free-tier Gemini quota (5 req/min, daily cap) exhausts quickly given DeepEval's multi-call architecture. Production use requires a paid API tier or a self-hosted judge model (e.g. Ollama + Llama 3).

---

## Key Findings

1. **First dataset evaluated (Kaggle synthetic) was discarded** — labels were found to be statistically independent of signal fields. 92% of rows using attack tools (Nmap, SQLMap) were labeled "benign," matching the overall class distribution exactly. This is a QA finding in itself: don't trust a label column without verifying it.

2. **Validator bug caught mid-build** — naive keyword matching misread negation, reporting 12/15 accuracy on what was actually 15/15 correct. Fixed with verdict-phrase matching and negation handling.

3. **Data lineage gap identified and fixed** — normalized records had no link back to their source row, making manual verification impossible. Fixed by adding `_source_row_index` to every normalized record.

4. **DeepEval free-tier quota exhausted** — DeepEval's multi-call-per-metric architecture hits rate limits faster than expected. Documented in the notebook with a clear production path forward.

---

## Tech Stack

| Component | Tool |
|-----------|------|
| Dataset | NSL-KDD (network intrusion benchmark) |
| Data processing | Python, pandas |
| LLM (PromptOps) | Gemini 2.5 Flash (google-genai) |
| LLM evaluation | DeepEval (FaithfulnessMetric, AnswerRelevancyMetric, GEval) |
| Environment | Google Colab |

---

## How to Run

1. Open the notebook in Google Colab
2. Add your Gemini API key as a Colab secret named `GEMINI_API_KEY`  
   (get a free key at https://aistudio.google.com/apikey)
3. Run cells top to bottom — dataset downloads automatically, no manual upload needed
4. Note: DeepEval cells require ~65s between metrics due to free-tier rate limits

---

## Project Structure

```
├── README.md
├── ai_qa_pipeline.ipynb        # Main notebook (all 6 steps)
└── scripts/                    # Individual step scripts (Colab-ready)
    ├── step1_nslkdd_ingest.py
    ├── step2_normalize.py
    ├── step3_4_promptops_validation.py
    ├── step5_manual_faithfulness_review.py
    └── step6_deepeval.py
```

---

## Author

**Nikhil Barot** — Senior QA Automation Engineer | AI/ML  
[LinkedIn](https://www.linkedin.com/in/nikhil-barot/) | nikhilbarot3@gmail.com
