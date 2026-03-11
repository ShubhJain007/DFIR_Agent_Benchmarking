# =============================================================================
# myconfig.example.py  –  Copy this to secgym/myconfig.py and fill in your keys
# =============================================================================
#
# HOW IT WORKS
# ------------
# run_exp.py uses --model <tag> and --eval_model <tag> to pick entries from
# CONFIG_LIST by matching the "tags" field. Each entry must have a unique tag.
#
# MINIMUM SETUP (two entries needed):
#   1. Agent model   → matched by  --model <tag>
#   2. Evaluator     → matched by  --eval_model <tag>
#
# Never commit this file with real keys — it is already in .gitignore.
# =============================================================================

CONFIG_LIST = [

    # ── Option A: OpenAI direct ───────────────────────────────────────────────
    {
        "model": "gpt-4.1",
        "api_key": "sk-YOUR_OPENAI_API_KEY_HERE",
        "tags": ["gpt-4.1"],
        "temperature": 0,
    },
    {
        "model": "gpt-4.1-nano",
        "api_key": "sk-YOUR_OPENAI_API_KEY_HERE",
        "tags": ["gpt-4.1-nano"],
        "temperature": 0,
    },

    # ── Option B: Anthropic (Claude) ─────────────────────────────────────────
    # Requires api_type="anthropic" — handled automatically by call_llm()
    {
        "model": "claude-haiku-4-5-20250929",
        "api_key": "sk-ant-YOUR_ANTHROPIC_API_KEY_HERE",
        "tags": ["claude-haiku-4-5"],
        "temperature": 0,
    },
    {
        "model": "claude-sonnet-4-5-20250929",
        "api_key": "sk-ant-YOUR_ANTHROPIC_API_KEY_HERE",
        "tags": ["claude-sonnet-4-5"],
        "temperature": 0,
    },

    # ── Option C: OpenRouter (proxies Claude, GPT, Gemini, etc.) ─────────────
    # Get a free key at https://openrouter.ai  — some models have free tier
    {
        "model": "google/gemini-2.0-flash-001",
        "api_key": "sk-or-v1-YOUR_OPENROUTER_KEY_HERE",
        "base_url": "https://openrouter.ai/api/v1",
        "api_type": "openai",
        "tags": ["gemini-flash"],
        "temperature": 0,
    },
    {
        "model": "anthropic/claude-haiku-4-5:beta",
        "api_key": "sk-or-v1-YOUR_OPENROUTER_KEY_HERE",
        "base_url": "https://openrouter.ai/api/v1",
        "api_type": "openai",
        "tags": ["claude-haiku-or"],
        "temperature": 0,
    },

    # ── Option D: Groq (free tier, fast inference) ───────────────────────────
    # Get a free key at https://console.groq.com
    {
        "model": "llama-3.3-70b-versatile",
        "api_key": "gsk_YOUR_GROQ_API_KEY_HERE",
        "base_url": "https://api.groq.com/openai/v1",
        "tags": ["groq-llama"],
        "temperature": 0,
    },

    # ── Evaluator entry (used by --eval_model flag) ───────────────────────────
    # Recommended: gpt-4o or gpt-4.1 for reliable evaluation scoring
    {
        "model": "gpt-4o",
        "api_key": "sk-YOUR_OPENAI_API_KEY_HERE",
        "tags": ["eval"],
        "temperature": 0,
    },

    # ── Azure OpenAI (optional) ───────────────────────────────────────────────
    # {
    #     "model": "gpt-4.1-nano",
    #     "base_url": "https://YOUR_RESOURCE.openai.azure.com",
    #     "api_type": "azure",
    #     "api_version": "2025-01-01-preview",
    #     "api_key": "YOUR_AZURE_KEY",
    #     "tags": ["gpt-4.1-nano"],
    # },
]

if len(CONFIG_LIST) == 0:
    print("Error: No config set in CONFIG_LIST — add your keys to secgym/myconfig.py")
