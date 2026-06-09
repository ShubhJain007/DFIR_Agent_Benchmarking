# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from azure.identity import get_bearer_token_provider, AzureCliCredential
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential

# token_provider = get_bearer_token_provider(
#     AzureCliCredential(), "https://cognitiveservices.azure.com/.default"
# )

# BE SURE TO include a "tags": [<model_name>] for each dictionary in the config_list to include the model name
# We will filter out the config list passed in to only include the model that model_name in the tags is equal to qa_gen_model
# config_list = [
#     {
#         "model": "some name",
#         "tags": ["gpt-4o"]
#     },
#     {
#         "model": "some name",
#         "tags": ["gpt-3.5"]
#     }
# ]
# If qa_gen_model = "gpt-4o", the config_list for qa_gen will be only the first dictionary in the config_list
# Similarly in run_exp.py, if you set --model gpt-4o, the config_list for the agent will be only the first dictionary in the config_list

_BEDROCK_BEARER = "YOUR_BEDROCK_BEARER_TOKEN"

CONFIG_LIST = [
    # ── Agent: Claude Sonnet 4.6 via AWS Bedrock (bearer token) ──────────────
    {
        "model":    "global.anthropic.claude-sonnet-4-6",
        "api_key":  _BEDROCK_BEARER,
        "base_url": "https://bedrock-runtime.us-east-1.amazonaws.com",
        "api_type": "bedrock",
        "tags":     ["claude-sonnet-bedrock"],
        "temperature": 0,
    },
    # ── Evaluator: also Claude Sonnet 4.6 via Bedrock (same model) ───────────
    {
        "model":    "global.anthropic.claude-sonnet-4-6",
        "api_key":  _BEDROCK_BEARER,
        "base_url": "https://bedrock-runtime.us-east-1.amazonaws.com",
        "api_type": "bedrock",
        "tags":     ["eval-bedrock"],
        "temperature": 0,
    },
    # ── Evaluator: Claude Haiku 4.5 via OpenRouter (OpenAI-compatible) ────────
    # The LLMEvaluator uses OpenAIWrapper internally — needs OpenAI-format API
    # OpenRouter proxies Claude so it works seamlessly as the evaluator
    # price: [input_per_1k, output_per_1k] in USD — suppresses autogen cost warning
    {
        "model": "anthropic/claude-haiku-4.5",
        "api_key": 'YOUR_OPENROUTER_API_KEY',
        "base_url": "https://openrouter.ai/api/v1",
        "tags": ["eval"],
        "api_type": "openai",
        "temperature": 0,
        "price": [0.0008, 0.004],        # $0.80/M input, $4.00/M output
    },
    # ── Agent fallback: Claude Haiku 4.5 via OpenRouter ──────────────────────
    {
        "model": "anthropic/claude-haiku-4-5:beta",
        "api_key": 'YOUR_OPENROUTER_API_KEY',
        "base_url": "https://openrouter.ai/api/v1",
        "tags": ["claude"],
        "api_type": "openai",
        "temperature": 0
    },
    # ── gpt-4o (kept as backup) ───────────────────────────────────────────────
    {
        "model": "gpt-4o",
        "api_key": "YOUR_OPENAI_API_KEY",
        "tags": ["eval-gpt"],
        "temperature": 0
    },
]

if len(CONFIG_LIST) == 0:
    print("Potential Error: No config set in CONFIG_LIST, please add your config list to the CONFIG_LIST variable in secgym/myconfig.py")
