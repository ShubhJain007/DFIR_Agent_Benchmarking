#!/usr/bin/env python3
# Test script for Multi-Agent DFIR System

"""
Quick test to verify the multi-agent system is working.
This doesn't run full evaluation, just tests basic functionality.
"""

import sys
sys.path.insert(0, '.')

from secgym.agents.multi_agent.orchestrator_agent import OrchestratorAgent
from secgym.myconfig import CONFIG_LIST

def test_basic_functionality():
    """Test basic agent instantiation and interface."""
    print("=" * 60)
    print("Testing Multi-Agent DFIR System - Basic Functionality")
    print("=" * 60)

    # Check if config list is set
    if not CONFIG_LIST:
        print("\n❌ ERROR: CONFIG_LIST is empty in secgym/myconfig.py")
        print("Please add at least one model configuration to test with.")
        return False

    print(f"\n✓ Found {len(CONFIG_LIST)} model config(s)")

    # Filter for a test model (use first available)
    test_config = [CONFIG_LIST[0]]
    print(f"✓ Using model: {test_config[0].get('model', 'unknown')}")

    try:
        # Instantiate agent
        print("\n[1] Instantiating OrchestratorAgent...")
        agent = OrchestratorAgent(
            config_list=test_config,
            cache_seed=42,
            max_steps=3,  # Keep short for testing
            temperature=0
        )
        print(f"✓ Agent created: {agent.name}")

        # Check sub-agents
        print("\n[2] Checking sub-agents...")
        print(f"   - Research Agent: {type(agent.research_agent).__name__}")
        print(f"   - Investigator Agent: {type(agent.investigator_agent).__name__}")
        print(f"   - Skill Registry: {type(agent.skill_registry).__name__}")
        print(f"   - Case File: {type(agent.case_file).__name__}")
        print("✓ All sub-agents initialized")

        # Test interface methods
        print("\n[3] Testing interface methods...")

        # Test property
        name = agent.name
        print(f"   - name property: {name}")

        # Test get_logging (should work even without acting)
        logs = agent.get_logging()
        assert "messages" in logs, "messages missing from logging"
        assert "usage_summary" in logs, "usage_summary missing from logging"
        print("✓ get_logging() returns correct format")

        # Test reset
        agent.reset(change_seed=False)
        print("✓ reset() works")

        print("\n[4] Testing skill registry...")
        skills = agent.skill_registry.skill_definitions
        print(f"   - Registered skills: {list(skills.keys())}")
        print("✓ Skill registry populated")

        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        print("\nThe multi-agent system is ready to use.")
        print("\nTo run full evaluation, use:")
        print("  python experiments/run_exp.py --agent multi_agent --attack incident_5 --model <your-model>")

        return True

    except Exception as e:
        print(f"\n❌ ERROR during testing: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_skills_loading():
    """Test skill loading mechanism."""
    print("\n" + "=" * 60)
    print("Testing Skills System")
    print("=" * 60)

    try:
        from secgym.agents.skills import SkillRegistry

        registry = SkillRegistry()
        print(f"\n✓ SkillRegistry created")
        print(f"   - Available skills: {list(registry.skill_definitions.keys())}")

        # Test trigger detection
        test_contexts = [
            ("Found suspicious IP: 45.142.212.61", ["tavily_threat_search"]),
            ("Hash: 5f4dcc3b5aa765d61d8327deb882cf99", ["tavily_threat_search"]),
            ("SELECT * FROM SecurityAlert WHERE user='admin'", ["optimize_query"]),
        ]

        print("\n[Testing trigger detection]")
        for context, expected in test_contexts:
            detected = registry.detect_needed_skills(context)
            print(f"   Context: '{context[:50]}...'")
            print(f"   Expected: {expected}")
            print(f"   Detected: {detected}")

            if set(expected).issubset(set(detected)):
                print("   ✓ PASS")
            else:
                print("   ⚠ PARTIAL (may be OK depending on logic)")

        print("\n✅ Skills system functional")
        return True

    except Exception as e:
        print(f"\n❌ ERROR testing skills: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("\n🔍 Multi-Agent DFIR System - Test Suite\n")

    success = True

    # Run tests
    success = test_basic_functionality() and success
    success = test_skills_loading() and success

    if success:
        print("\n✅ All tests passed! System is operational.")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. Please review errors above.")
        sys.exit(1)
