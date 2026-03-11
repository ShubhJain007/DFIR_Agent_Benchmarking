# Multi-Agent DFIR System for ExCyTIn-Bench

> A drop-in replacement agent for the [Microsoft SecRL / ExCyTIn-Bench](https://github.com/microsoft/SecRL) benchmark that addresses the three biggest failure modes observed across Category A models.

---

## What This Adds

Three improvements on top of the baseline SecRL agent, targeted at the 40–58% "had data but submitted the wrong answer" failure rate seen in top models like claude-opus-4.5 (0.640 avg reward) and gpt-5.1 (0.599):

| # | Improvement | What it fixes |
|---|-------------|---------------|
| 1 | **Schema Injection** (`schema_manager.py`) | Eliminates the 3–4 wasted SHOW TABLES / DESCRIBE steps at the start of every question (~12–15% of step budget) |
| 2 | **Answer Extractor Agent** (`extractor_agent.py`) | Validates the candidate answer before submission — fixes the 40–58% "data visible but wrong pick" failure |
| 3 | **Incident Memory** (`incident_memory.py`) | Caches facts across questions within one incident — later questions get a head-start from already-solved ones |

**New files:**
```
secgym/agents/multi_agent/
  ├── schema_manager.py      # One-time schema discovery via execute_query() (0 agent steps used)
  ├── extractor_agent.py     # LLM-based answer validation before submit
  ├── incident_memory.py     # Cross-question keyword-indexed fact store
  ├── orchestrator_agent.py  # Main coordinator (modified to wire all three)
  └── investigator_agent.py  # Modified: accepts schema_context param
```

**Modified files:**
```
secgym/agents/__init__.py    # Exports OrchestratorAgent
experiments/run_exp.py       # Registers "multi_agent_dfir", adds schema + memory hooks
```

---

## Setup

### 1. Clone and install base dependencies

```bash
git clone https://github.com/ShubhJain007/DFIR_Agent_Benchmarking.git
cd DFIR_Agent_Benchmarking
pip install -r requirements.txt
```

### 2. Set up the database

Follow the original [SecRL database setup](https://github.com/microsoft/SecRL#setup) to configure MySQL and populate the ExCyTIn incident databases.

### 3. Add your API keys

```bash
cp secgym/myconfig.example.py secgym/myconfig.py
```

Open `secgym/myconfig.py` and fill in your keys. The file has examples for OpenAI, Anthropic, OpenRouter, and Groq.

**Key concept:** every entry in `CONFIG_LIST` needs a `"tags"` field. The tag is what you pass to `--model` and `--eval_model` on the command line.

**Minimum config (two entries needed):**

```python
# secgym/myconfig.py
CONFIG_LIST = [
    # 1. The agent model  →  used with --model
    {
        "model": "gpt-4.1-nano",
        "api_key": "sk-YOUR_OPENAI_KEY",
        "tags": ["gpt-4.1-nano"],
        "temperature": 0,
    },
    # 2. The evaluator model  →  used with --eval_model
    {
        "model": "gpt-4o",
        "api_key": "sk-YOUR_OPENAI_KEY",
        "tags": ["eval"],
        "temperature": 0,
    },
]
```

**Where to get free/cheap keys:**

| Provider | Free tier | Notes |
|----------|-----------|-------|
| [OpenRouter](https://openrouter.ai) | Some models free | Proxies Claude, GPT, Gemini — one key for all |
| [Groq](https://console.groq.com) | Free with rate limits | Fast Llama inference, great for dev/trial runs |
| [Google AI Studio](https://aistudio.google.com) | Gemini Flash free | Use via OpenRouter or direct API |
| Anthropic Console | $5 on signup | [console.anthropic.com](https://console.anthropic.com) |
| OpenAI | No free tier | Must add payment method |

---

## Running the Agent

### Command format

```bash
cd experiments
python run_exp.py \
  --agent multi_agent_dfir \
  --model <agent-tag> \
  --eval_model <eval-tag> \
  [options]
```

The `--model` tag must match a `"tags"` entry in your `CONFIG_LIST` for the **agent**.
The `--eval_model` tag must match a `"tags"` entry for the **evaluator** (scores answers).

---

### Quick start — trial run (2 questions only, ~$0.02–$1.50)

```bash
python run_exp.py \
  --agent multi_agent_dfir \
  --model gpt-4.1-nano \
  --eval_model eval \
  --trial_run
```

This runs 2 questions from the first incident and stops. Use it to verify everything works before spending money.

---

### Single incident (recommended for development)

```bash
# Cheap: gpt-4.1-nano agent  (~$1)
python run_exp.py \
  --agent multi_agent_dfir \
  --model gpt-4.1-nano \
  --eval_model eval \
  --max_steps 15

# Mid-range: claude-haiku  (~$26 for incident 5)
python run_exp.py \
  --agent multi_agent_dfir \
  --model claude-haiku-4-5 \
  --eval_model eval \
  --max_steps 15
```

> By default all 8 incidents run. To restrict to one, use `--trial_run` or modify the `ATTACKS` list in `run_exp.py` temporarily.

---

### Full benchmark (all 8 incidents)

```bash
# Best quality vs. cost tradeoff
python run_exp.py \
  --agent multi_agent_dfir \
  --model claude-sonnet-4-5 \
  --eval_model eval \
  --max_steps 25 \
  --cache_seed 200
```

| Agent model | Est. full benchmark cost | Expected avg reward |
|-------------|--------------------------|---------------------|
| gpt-4.1-nano | ~$7 | Lower bound / dev |
| claude-haiku-4-5 | ~$155 | Category B baseline |
| gpt-4.1 | ~$59 | Mid |
| claude-sonnet-4-5 | ~$435 | Targets >0.64 |
| o3 | ~$488 | Targets >0.64 |

---

### All available flags

```
--agent         multi_agent_dfir  (use this for the new system)
--model         Tag from CONFIG_LIST for the agent LLM
--eval_model    Tag from CONFIG_LIST for the evaluator LLM
--max_steps     Max SQL steps per question (default 15, benchmark uses 25)
--temperature   LLM temperature (default 0)
--cache_seed    AutoGen cache seed (default 131)
--num_trials    Retry failed questions N times (default 1)
--trial_run     Run only 2 questions then stop (for verification)
--overwrite     Re-run questions already in the save file
--layer         alert (default) | log | alert_only
--full_db       Use the full AlpineSkiHouse DB (requires extra setup)
```

---

## How It Works (Technical Detail)

### Schema Injection flow

```
for each incident:
  ExcytinEnv created
  SchemaManager.discover()       ← SHOW TABLES + DESCRIBE via execute_query()
                                    (0 agent steps consumed)
  agent.load_schema(schema_str)  ← injected into InvestigatorAgent system prompt

for each question:
  agent.reset()                  ← schema survives reset(), only memory is cleared per-question
  InvestigatorAgent already knows full schema
  → skips SHOW TABLES / DESCRIBE → saves 3-4 steps per question
```

### Answer Extraction flow

```
InvestigatorAgent decides to submit[answer]
  → OrchestratorAgent intercepts
  → ExtractorAgent.extract(question, candidate, last_sql_result)
       - LLM reads question + SQL result + candidate
       - outputs ANSWER: X | CONFIDENCE: 0.0-1.0
  → confidence >= 0.6 → submit validated answer
  → confidence < 0.6 → suppress submit, investigator keeps working
```

### Incident Memory flow

```
Question 1 solved with reward=1:
  run_exp.py calls incident_memory.store_from_answer(question, answer)
  → "IP address of attacker" → {"attacker_ip": "1.2.3.4"}

Question 7 asks "What IP did the attacker use?":
  incident_memory.get_context_block(question)
  → "Previously established: attacker_ip = 1.2.3.4 (from Q1)"
  → prepended to observation before InvestigatorAgent sees it
```

---

## Results Location

Results are saved to `experiments/final_results/<run_name>/`:
- `agent_incident_<N>.json` — full trajectory + token usage per question
- `env_incident_<N>.json`  — environment state + rewards
- `results.txt`            — summary scores per incident

---

## Architecture Overview

```
run_exp.py
│
├─ SchemaManager          (once per incident)
│    └─ execute_query()   ← zero step cost
│
└─ OrchestratorAgent      (one per run, reset per question)
     ├─ IncidentMemory    (persists across questions, cleared per incident)
     ├─ InvestigatorAgent (schema in system prompt, does SQL investigation)
     ├─ ResearchAgent     (threat intel lookup for external IPs/hashes)
     └─ ExtractorAgent    (validates answer before submit)
```

---

## Baseline Comparison (Category A models, full benchmark)

| Model | Agent | Avg Reward |
|-------|-------|-----------|
| claude-opus-4.5 | BaselineAgent | 0.640 |
| gpt-5.1 (high reasoning) | BaselineAgent | 0.599 |
| o3 | BaselineAgent | 0.522 |
| claude-sonnet-4.5 | BaselineAgent | 0.477 |
| claude-sonnet-4.5 | **MultiAgentDFIR** | 🔄 run to find out |

---

## Based On

- [Microsoft SecRL / ExCyTIn-Bench](https://github.com/microsoft/SecRL) — original benchmark and environment
- AG2 / AutoGen framework (`pyautogen==0.2.35`)
