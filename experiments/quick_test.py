#!/usr/bin/env python3
"""
Quick test script for multi-agent system on N questions
Usage: python3 experiments/quick_test.py --num_questions 5
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from secgym.excytin_env import ExcytinEnv
from secgym.evaluator import LLMEvaluator
from secgym.myconfig import CONFIG_LIST
from secgym.agents import OrchestratorAgent, ReActAgent
from experiments.run_exp import run_experiment, filter_config_list
import argparse

def quick_test(num_questions=3, agent_type="multi_agent", attack="incident_5", model_tag="llama-3.3-70b-versatile"):
    """
    Quick test on N questions

    Args:
        num_questions: Number of questions to test (default: 3)
        agent_type: "multi_agent" or "react" for comparison
        attack: Which incident to test
        model_tag: Model tag from CONFIG_LIST
    """

    print(f"\n{'='*60}")
    print(f"Quick Test: {agent_type} on {num_questions} questions")
    print(f"Attack: {attack}, Model: {model_tag}")
    print(f"{'='*60}\n")

    # Filter config
    agent_config = filter_config_list(CONFIG_LIST, model_tag)
    eval_config = filter_config_list(CONFIG_LIST, model_tag)

    if not agent_config:
        print(f"❌ No config found for model tag: {model_tag}")
        print(f"Available tags: {[c.get('tags', []) for c in CONFIG_LIST]}")
        return

    # Create evaluator
    evaluator = LLMEvaluator(
        config_list=eval_config,
        cache_seed=41,
        ans_check_reflection=False,  # Faster for testing
        sol_check_reflection=False,
        step_checking=False,
        strict_check=False,
    )

    # Create environment
    import tempfile
    temp_save = tempfile.mktemp(suffix='.jsonl')  # Temporary file for quick test
    env = ExcytinEnv(
        attack=attack,
        evaluator=evaluator,
        save_file=temp_save,
        max_steps=10,  # Shorter for testing
        split="test",
        use_full_db=False,
        layer="alert",
    )

    # Create agent
    if agent_type == "multi_agent":
        agent = OrchestratorAgent(
            config_list=agent_config,
            cache_seed=41,
            temperature=0,
            max_steps=10,
        )
    elif agent_type == "react":
        agent = ReActAgent(
            config_list=agent_config,
            cache_seed=41,
            temperature=0,
            max_steps=10,
        )
    else:
        raise ValueError(f"Unknown agent type: {agent_type}")

    print(f"✓ Agent: {agent.name}")
    print(f"✓ Environment: {attack} (layer: alert)")
    print(f"✓ Questions to test: {num_questions}\n")

    # Run experiment
    temp_agent_save = tempfile.mktemp(suffix='_agent.jsonl')
    success, tested, avg_reward = run_experiment(
        agent=agent,
        thug_env=env,
        save_agent_file=temp_agent_save,
        num_test=num_questions,  # KEY: Limit to N questions
        num_trials=1,
        overwrite=True,
        trial_run=False,
    )

    # Print results
    print(f"\n{'='*60}")
    print(f"Results Summary")
    print(f"{'='*60}")
    print(f"Questions tested: {tested}")
    print(f"Successful: {success}")
    print(f"Success rate: {success/tested*100:.1f}%")
    print(f"Average reward: {avg_reward/tested:.3f}")
    print(f"{'='*60}\n")

    return success, tested, avg_reward


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Quick test multi-agent system")
    parser.add_argument("--num_questions", type=int, default=3, help="Number of questions to test")
    parser.add_argument("--agent", choices=["multi_agent", "react"], default="multi_agent", help="Agent type")
    parser.add_argument("--attack", default="incident_5", help="Incident to test")
    parser.add_argument("--model", default="llama-3.3-70b-versatile", help="Model tag")

    args = parser.parse_args()

    quick_test(
        num_questions=args.num_questions,
        agent_type=args.agent,
        attack=args.attack,
        model_tag=args.model,
    )
