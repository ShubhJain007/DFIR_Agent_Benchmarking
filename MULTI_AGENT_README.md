# Multi-Agent DFIR System (MVP) - Implementation Complete ✅

## Overview

A specialized multi-agent system for Digital Forensics and Incident Response (DFIR) investigations in the SecRL benchmark. This MVP combines **Research** and **Investigator** agents with dynamically-loaded skills to enhance investigation quality while maintaining full compatibility with the existing evaluation framework.

## Architecture

```
User Question → Orchestrator → [Research | Investigator] → SQL/Answer
                     ↓
            Skills Registry (4 essential skills)
                     ↓
            Case File (lightweight shared memory)
```

### Components

1. **OrchestratorAgent** (`secgym/agents/multi_agent/orchestrator_agent.py`)
   - Main coordinator implementing standard agent interface
   - Routes between Research and Investigator agents
   - Manages context and triggers
   - Fully compatible with SecRL evaluation framework

2. **ResearchAgent** (`secgym/agents/multi_agent/research_agent.py`)
   - External threat intelligence specialist
   - Uses Tavily API for real-time IOC enrichment
   - Caches results to minimize API calls
   - Triggered automatically for: external IPs, file hashes, unknown entities

3. **InvestigatorAgent** (`secgym/agents/multi_agent/investigator_agent.py`)
   - SQL-based forensic investigator
   - Adapted from ReActAgent with enhanced capabilities
   - Uses Thought-Action pattern with ReAct examples
   - Access to case file for investigation context

4. **SkillRegistry** (`secgym/agents/skills/__init__.py`)
   - Dynamic skill loading system
   - Prevents context bloat by loading skills on-demand
   - Pattern-based trigger detection

5. **CaseFile** (`secgym/agents/multi_agent/case_file.py`)
   - Lightweight shared memory
   - Tracks entities, findings, SQL history, external intelligence

## Skills (MVP - 4 Essential Skills)

### Research Skills
- **tavily_threat_search**: Real-time threat intelligence lookups (IPs, hashes, malware)

### Investigation Skills
- **extract_entities**: Regex-based extraction of IPs, users, hosts, hashes, domains, emails
- **build_timeline**: Chronological event ordering and timeline construction
- **optimize_query**: Automatic LIMIT clause addition, query validation

## Installation & Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `tavily-python>=0.3.0` - For threat intelligence research
- All existing SecRL dependencies

### 2. Configure Tavily API Key

```bash
export TAVILY_API_KEY="your-tavily-api-key-here"
```

Get a free API key at: https://tavily.com

Alternatively, add to `~/.bashrc` or `~/.zshrc`:
```bash
echo 'export TAVILY_API_KEY="your-key"' >> ~/.bashrc
source ~/.bashrc
```

### 3. Configure Model

Edit `secgym/myconfig.py` and add your LLM configuration to `CONFIG_LIST`:

```python
CONFIG_LIST = [
    {
        "model": "gpt-4",
        "api_key": "your-openai-key",
        "tags": ["gpt-4"],
    },
    # ... more configs
]
```

### 4. Verify Installation

```bash
python3 test_multi_agent.py
```

Expected output:
```
✅ ALL TESTS PASSED!
The multi-agent system is ready to use.
```

## Usage

### Run Evaluation

```bash
python experiments/run_exp.py \
  --agent multi_agent \
  --attack incident_5 \
  --layer alert \
  --model gpt-4 \
  --num_questions 10 \
  --max_steps 15
```

### Parameters

- `--agent multi_agent` - Use the new multi-agent system
- `--attack` - Incident to evaluate (incident_5, incident_38, etc.)
- `--layer` - Database access level (alert, log, incident)
- `--model` - Model tag from CONFIG_LIST
- `--num_questions` - Number of questions to evaluate
- `--max_steps` - Maximum investigation steps per question

### Compare with Baseline

```bash
# Run multi-agent
python experiments/run_exp.py --agent multi_agent --attack incident_5 --model gpt-4 --num_questions 10

# Run baseline for comparison
python experiments/run_exp.py --agent react --attack incident_5 --model gpt-4 --num_questions 10
```

## How It Works

### Investigation Flow

1. **Question received** → Orchestrator stores in case file
2. **Research check** → If external IP/hash/unknown entity detected → Research agent enriches context
3. **Investigation** → Investigator agent queries database with (enriched) context
4. **Skill loading** → Skills loaded automatically based on triggers:
   - External IP detected → `tavily_threat_search` loaded
   - SQL query detected → `optimize_query` loaded
   - Entities in results → `extract_entities` loaded
5. **Result processing** → Observation returned to investigator
6. **Repeat** until answer found or max steps reached
7. **Submit** → Final answer submitted for evaluation

### Research Triggers (Automatic)

Research agent is triggered when observation contains:
- **External IPs**: Public IP addresses (not 10.*, 192.168.*, 172.16-31.*, 127.*)
- **File hashes**: MD5 (32 hex) or SHA256 (64 hex) strings
- **Uncertainty keywords**: "unknown", "suspicious", "malicious", "what is", "identify"

### Example Interaction

```
[Step 1] User: "What IP did the attacker use?"
  → Investigator: execute[SELECT DISTINCT source_ip FROM DeviceNetworkEvents WHERE alert_id='A-123']
  → Observation: Returns IP 45.142.212.61

[Step 2] Orchestrator detects external IP → Triggers research
  → Research: "45.142.212.61 is a known C2 server (AbuseIPDB: 100% malicious)"
  → Investigator receives enriched observation
  → Investigator: submit[The attacker used IP 45.142.212.61, a known C2 server]
```

## Output Format (Evaluation Compatible)

The orchestrator returns the **exact same format** as existing agents:

```python
# act() returns
(action: str, is_submit: bool)

# get_logging() returns
{
    "messages": [...],           # Conversation history
    "usage_summary": {...},      # Token usage
    "skills_used": [...],        # MVP: Loaded skills
    "research_calls": 3,         # MVP: Number of Tavily calls
    "case_file_summary": {...}   # MVP: Investigation metadata
}
```

## File Structure

```
secgym/agents/
├── multi_agent/
│   ├── __init__.py
│   ├── orchestrator_agent.py      [200 lines - Main coordinator]
│   ├── research_agent.py          [100 lines - Tavily wrapper]
│   ├── investigator_agent.py      [150 lines - SQL forensics]
│   └── case_file.py               [80 lines - Shared memory]
├── skills/
│   ├── __init__.py                [100 lines - SkillRegistry]
│   ├── research_skills.py         [80 lines - Tavily integration]
│   └── investigation_skills.py    [120 lines - 3 core helpers]
```

**Total: ~830 lines of new code**

## Limitations & Future Work

### Current Limitations (MVP)

1. **No Analyst Agent**: Investigator handles basic synthesis
2. **Limited Skills**: Only 4 core skills (no anomaly detection, correlation, etc.)
3. **No Context Compression**: May hit token limits on very long investigations
4. **No Reflexion**: Doesn't learn from past failures
5. **Simple Research Triggers**: Pattern-based, may miss some opportunities

### Post-MVP Enhancements

After validating MVP on SecRL benchmark:

1. **Add Analyst Agent** - Dedicated root cause analysis and synthesis
2. **More Skills** - Anomaly detection, correlation engine, log parsing, base64 decoding
3. **Context Management** - Automatic compression at token limits
4. **Reflexion** - Learn from failed attempts via replay buffer
5. **Advanced Research** - VirusTotal integration, MITRE ATT&CK mapping, IP geolocation
6. **Cost Optimization** - Use cheaper models for investigation, expensive for research/analysis

## Performance Expectations

### Success Criteria

- ✅ **Compatibility**: No changes to evaluation framework needed
- 🎯 **Accuracy**: Target ≥ baseline agent performance
- 📊 **Efficiency**: Should use ≤ 1.5x tokens (research overhead acceptable)
- 🔧 **Skills**: Successfully loads and uses skills per investigation
- 🔍 **Research**: Makes meaningful Tavily calls (not every step)

### Advantages Over Baseline

1. **External Knowledge**: Enriches investigation with real-time threat intel
2. **Domain Expertise**: Specialized agents with focused prompts
3. **Skill Loading**: Prevents context bloat by loading only needed capabilities
4. **Shared Memory**: Case file tracks investigation progress across steps
5. **Extensible**: Easy to add new agents and skills post-MVP

## Troubleshooting

### Tavily API Errors

```
Error: Tavily API key not configured
```
**Solution**: Set environment variable
```bash
export TAVILY_API_KEY="your-key"
```

### Import Errors

```
ModuleNotFoundError: No module named 'tavily'
```
**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

### No Config Error

```
Potential Error: No config set in CONFIG_LIST
```
**Solution**: Add your model config to `secgym/myconfig.py`

### Test Failures

```bash
# Run diagnostic test
python3 test_multi_agent.py

# Check specific component
python3 -c "from secgym.agents import OrchestratorAgent; print('OK')"
```

## Contributing

To extend the multi-agent system:

1. **Add new skills**: Create function in `secgym/agents/skills/`
2. **Register skill**: Add to `SkillRegistry.skill_definitions` with triggers
3. **Add new agent**: Create in `secgym/agents/multi_agent/`, integrate with orchestrator
4. **Update orchestrator**: Modify routing logic in `orchestrator_agent.py`

## References

- **SecRL Benchmark**: https://github.com/microsoft/SecRL
- **Tavily API**: https://docs.tavily.com
- **ReAct Pattern**: Yao et al., "ReAct: Synergizing Reasoning and Acting in Language Models"
- **Plan File**: `/Users/batputer/.claude/plans/imperative-fluttering-ritchie.md`

## License

Copyright (c) Microsoft Corporation. Licensed under the MIT License.

---

**Status**: ✅ MVP Implementation Complete
**Next Step**: Run full evaluation on SecRL benchmark and compare with baseline agents
