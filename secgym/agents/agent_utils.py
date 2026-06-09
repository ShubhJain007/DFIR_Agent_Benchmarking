# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import re
from autogen import OpenAIWrapper
import time
from typing import List
from openai.types.chat import ChatCompletion
from openai import RateLimitError as OpenAIRateLimitError
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import ChatCompletions
from anthropic import APIStatusError as AnthropicAPIStatusError


def msging(msg: str, role: str="user"):
    return {"role": role, "content": msg}


# ---------------------------------------------------------------------------
# Bedrock helpers
# ---------------------------------------------------------------------------

class BedrockUsageAdapter:
    """Maps Bedrock response usage dict to OpenAI model_dump() format."""
    def __init__(self, usage_dict: dict):
        self._in  = usage_dict.get("input_tokens", 0)
        self._out = usage_dict.get("output_tokens", 0)

    def model_dump(self):
        return {
            "prompt_tokens":     self._in,
            "completion_tokens": self._out,
            "total_tokens":      self._in + self._out,
        }


class BedrockResponseAdapter:
    """
    Wraps a raw Bedrock JSON response dict to look like an OpenAI ChatCompletion,
    so it's compatible with the update_model_usage / choices[0].message.content
    pattern used throughout the agents.
    """
    def __init__(self, response_dict: dict):
        self.model = response_dict.get("model", "claude-sonnet-4-6")
        # Extract the text from content blocks (skip thinking blocks)
        content_blocks = response_dict.get("content", []) or []
        text = next(
            (b["text"] for b in content_blocks if b.get("type") == "text"),
            "",
        )
        self.choices = [
            type("Choice", (), {
                "message": type("Message", (), {"content": text})()
            })()
        ]
        self.usage = BedrockUsageAdapter(response_dict.get("usage", {}))


def call_llm_bedrock(
        config_entry: dict,
        messages: list,
        retry_num: int = 10,
        retry_wait_time: int = 5,
        temperature: float = 0,
        use_thinking: bool = True,
        thinking_budget: int = 10000,
) -> BedrockResponseAdapter:
    """
    Call a Claude model via Amazon Bedrock using the bearer-token API key.

    Uses direct httpx requests with:
      - Authorization: Bearer {token}  (Bedrock's "Call with Bearer Token" auth)
      - POST /model/{model}/invoke    (Bedrock runtime endpoint)

    Args:
        config_entry   : single CONFIG_LIST entry with keys: model, api_key, base_url
        messages       : OpenAI-style message list (system + user/assistant turns)
        use_thinking   : enable extended thinking (True for investigator, False for extractor)
        thinking_budget: token budget for thinking blocks (must be >= 1024)
    """
    import httpx
    import urllib.parse

    token    = config_entry["api_key"]
    model    = config_entry["model"]
    base_url = config_entry.get("base_url",
                                "https://bedrock-runtime.us-east-1.amazonaws.com")

    # Build the correct Bedrock invoke URL
    model_encoded = urllib.parse.quote(model, safe=":")
    invoke_url = f"{base_url.rstrip('/')}/model/{model_encoded}/invoke"

    # Separate system prompt from conversation messages (Bedrock format)
    system_content = next(
        (m["content"] for m in messages if m["role"] == "system"), None
    )
    conv_messages = [m for m in messages if m["role"] != "system"]

    # Build the request body in Bedrock / Anthropic native format
    body: dict = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens":        16000,
        "messages":          conv_messages,
    }
    if system_content:
        body["system"] = system_content
    if use_thinking:
        # Extended thinking requires budget_tokens >= 1024
        budget = max(thinking_budget, 1024)
        body["thinking"] = {"type": "enabled", "budget_tokens": budget}
        # thinking mode ignores temperature — don't set it
    else:
        body["temperature"] = temperature

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }

    for attempt in range(retry_num):
        try:
            resp = httpx.post(invoke_url, headers=headers, json=body, timeout=120)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Bedrock HTTP {resp.status_code}: {resp.text[:300]}"
                )
            return BedrockResponseAdapter(resp.json())
        except Exception as e:
            if attempt < retry_num - 1:
                wait = retry_wait_time * (2 ** attempt)
                print(f"[Bedrock] Error: {e}. Retrying in {wait}s… ({attempt+1}/{retry_num})")
                time.sleep(wait)
            else:
                raise

def search_parser(action: str) -> tuple:
    """
    Parse search[query] actions from the investigator.

    Returns:
        (query_str, is_search)  — is_search=True when a search action was detected
    """
    clean = action.replace("`", "")
    if "search[" in clean:
        pattern = r'search\[(.*)\]'
        matches = re.findall(pattern, clean, re.DOTALL)
        if matches:
            return matches[0].strip(), True
    return action, False


def sql_parser(action: str, code_block=False):
    # remove ` in the str
    action = action.replace("`", "")
    if "submit[" in action:
        pattern = r'submit\[(.*)\]'
        submit = True
    else:
        if code_block:
            pattern = r'```sql(.*?)```'
        pattern = r'execute\[(.*)\]'
        submit = False

    matches = re.findall(pattern, action, re.DOTALL)
    if len(matches) > 0:
        action = matches[0]
        if ";" in action:
            return action[:action.index(";")], True, submit
        return action, True, submit
    return action, False, submit

def call_llm_foundry(
        client:ChatCompletionsClient, 
        model:str,
        messages:List[str], 
        retry_num=10, 
        retry_wait_time=5,
        temperature=None,
        stop=None,
    ) -> ChatCompletions:

    for _ in range(retry_num):
        try: 
            response = client.complete(messages=messages, temperature=temperature, stop=stop)
            break
        except TimeoutError as e:
            time.sleep(retry_wait_time)
    return response

def update_total_usage(total_usage, new_usage):
    """
    Recursively update the total_usage dictionary with values from new_usage.
    
    Parameters:
    - total_usage (dict): The running total usage dictionary.
    - new_usage (dict): The new usage data to be added.
    """
    for key, value in new_usage.items():
        if isinstance(value, dict):
            # Initialize a nested dictionary if it doesn't exist.
            if key not in total_usage:
                total_usage[key] = {}
            update_total_usage(total_usage[key], value)
        elif isinstance(value, int):
            # Initialize the key to 0 if it doesn't exist.
            if key not in total_usage:
                total_usage[key] = 0
            total_usage[key] += value

def update_model_usage(total_usage_by_model:dict, model_name:str, usage_dict:dict):
    """
    Update the total usage for a given model with the new response data.
    
    Parameters:
    - total_usage_by_model (dict): Dictionary mapping model names to their cumulative usage.
    - model_name (str): The name of the model.
    - usage_dict (dict): The new usage data to be added.
    """
    assert isinstance(total_usage_by_model, dict), "total_usage_by_model should be a dictionary"
    assert isinstance(model_name, str), "model_name should be a string"
    assert isinstance(usage_dict, dict), "usage_dict should be a dictionary"
    # If the model is not in the total_usage_by_model, initialize its usage dictionary.
    if model_name not in total_usage_by_model:
        total_usage_by_model[model_name] = {}
    
    update_total_usage(total_usage_by_model[model_name], usage_dict)


def call_llm(
        client:OpenAIWrapper, 
        model:str,
        messages:List[str], 
        retry_num=10, 
        retry_wait_time=5,
        temperature=None,
        stop=None
    ) -> ChatCompletion:

    for attempt in range(retry_num):
        try: 
            if "o1" in model:
                messages[0]['role'] = 'user'
                response = client.create(messages=messages, model=model)
            elif "o3" in model:
                response = client.create(messages=messages, model=model)
            elif "gpt-5" in model:
                #by default running at reasoning level high
                response = client.create(messages=messages, model=model, temperature=temperature, stop=stop, reasoning_effort="medium")
            elif "claude" in model and not model.startswith("anthropic/"):
                try:
                    response = client.create(messages=messages, model=model, temperature=temperature, stop=stop, thinking={"type": "enabled","budget_tokens": 10000})
                except AnthropicAPIStatusError as e:
                    if attempt < retry_num - 1:  # Don't sleep on the last retry
                        wait_time = retry_wait_time * (2 ** attempt)  # Exponential backoff
                        time.sleep(wait_time)
                        continue
                    else:
                        raise  # Re-raise on the last attempt
            else:
                response = client.create(messages=messages, model=model, temperature=temperature, stop=stop)
            break
        except OpenAIRateLimitError as e:
            if attempt < retry_num - 1:  # Don't sleep on the last retry
                wait_time = retry_wait_time * (2 ** attempt)  # Exponential backoff
                print(f"Rate limit error encountered. Retrying in {wait_time} seconds... (Attempt {attempt + 1}/{retry_num})")
                time.sleep(wait_time)
                continue
            else:
                raise  # Re-raise on the last attempt
        except TimeoutError as e:
            if attempt < retry_num - 1:
                time.sleep(retry_wait_time)
            else:
                raise
    return response
