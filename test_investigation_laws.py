#!/usr/bin/env python3
"""
Test script to verify Investigation Laws are properly incorporated
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from secgym.agents.multi_agent.investigator_agent import INVESTIGATOR_PROMPT

print("="*80)
print("VERIFYING INVESTIGATION LAWS IN INVESTIGATOR PROMPT")
print("="*80)

# Check for Critical Schema Reference
if "📊 CRITICAL SCHEMA REFERENCE" in INVESTIGATOR_PROMPT:
    print("✅ Critical Schema Reference section found")
else:
    print("❌ Critical Schema Reference section MISSING")

# Check for Investigation Laws
if "⚖️ INVESTIGATION LAWS" in INVESTIGATOR_PROMPT:
    print("✅ Investigation Laws section found")
else:
    print("❌ Investigation Laws section MISSING")

# Check for specific laws
laws_to_check = [
    ("NO GUESSING", "Law #1: NO GUESSING"),
    ("JSON FALLBACK", "Law #2: JSON FALLBACK"),
    ("TIMELINE PRECISION", "Law #3: TIMELINE PRECISION"),
    ("ENTITY PIVOTING", "Law #4: ENTITY PIVOTING"),
    ("SELECTION VALIDATION", "Law #5: SELECTION VALIDATION"),
]

print("\nChecking individual Investigation Laws:")
for keyword, description in laws_to_check:
    if keyword in INVESTIGATOR_PROMPT:
        print(f"  ✅ {description}")
    else:
        print(f"  ❌ {description} MISSING")

# Check for critical schema tables
critical_tables = [
    "AlertInfo",
    "AlertEvidence",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
]

print("\nChecking critical table schemas:")
for table in critical_tables:
    if table in INVESTIGATOR_PROMPT:
        print(f"  ✅ {table} schema present")
    else:
        print(f"  ❌ {table} schema MISSING")

# Check for AdditionalFields mention (critical for Fix #2)
if "AdditionalFields" in INVESTIGATOR_PROMPT:
    print("\n✅ AdditionalFields mentioned (Fix #2: Missing Contextual Correlation)")
else:
    print("\n❌ AdditionalFields NOT mentioned - Fix #2 incomplete!")

print("\n" + "="*80)
print("Prompt Length:", len(INVESTIGATOR_PROMPT), "characters")
print("="*80)

# Print first 1000 characters for verification
print("\nFirst 1000 characters of prompt:")
print("-"*80)
print(INVESTIGATOR_PROMPT[:1000])
print("-"*80)
