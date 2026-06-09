# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Research Skills - External threat intelligence lookup using Tavily
"""

import os
from typing import Dict, List, Optional
import json


def tavily_threat_search(query: str, search_type: str = "threat_intel", max_results: int = 3) -> Dict:
    """
    Search for threat intelligence using Tavily API.

    Args:
        query: Entity to research (IP, hash, malware name, etc.)
        search_type: Type of search - "threat_intel", "cve", "ioc", "tool"
        max_results: Maximum number of results to return

    Returns:
        Dictionary with:
        {
            "entity": str,
            "threat_context": str,  # Brief summary
            "sources": list,        # URLs
            "confidence": float     # 0-1
        }
    """
    try:
        from tavily import TavilyClient
    except ImportError:
        return {
            "entity": query,
            "threat_context": "Tavily not installed. Run: pip install tavily-python",
            "sources": [],
            "confidence": 0.0
        }

    # Get API key
    api_key = "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"
    if not api_key:
        return {
            "entity": query,
            "threat_context": "Tavily API key not configured. Set TAVILY_API_KEY environment variable.",
            "sources": [],
            "confidence": 0.0
        }

    try:
        client = TavilyClient(api_key=api_key)

        # Enhance query based on search type
        search_queries = {
            "threat_intel": f"{query} threat intelligence malware cybersecurity",
            "cve": f"CVE {query} vulnerability exploit",
            "ioc": f"{query} indicator of compromise threat",
            "tool": f"{query} malware tool technique MITRE"
        }

        enhanced_query = search_queries.get(search_type, query)

        # Perform search
        response = client.search(
            query=enhanced_query,
            max_results=max_results,
            search_depth="advanced",  # More thorough results
            include_domains=["mitre.org", "cve.mitre.org", "attack.mitre.org",
                            "virustotal.com", "abuse.ch", "urlhaus.abuse.ch",
                            "threatpost.com", "bleepingcomputer.com"],
        )

        # Extract and summarize results
        threat_context_parts = []
        sources = []

        if response.get("results"):
            for result in response["results"][:max_results]:
                content = result.get("content", "")
                url = result.get("url", "")

                if content:
                    # Take first 200 chars of each result
                    summary = content[:200].strip()
                    if summary:
                        threat_context_parts.append(summary)

                if url:
                    sources.append(url)

        # Use Tavily's answer if available (it's a summary)
        if response.get("answer"):
            threat_context = response["answer"]
        elif threat_context_parts:
            threat_context = " | ".join(threat_context_parts)
        else:
            threat_context = f"No threat intelligence found for: {query}"

        # Simple confidence based on number of results
        confidence = min(len(sources) / max_results, 1.0)

        return {
            "entity": query,
            "threat_context": threat_context,
            "sources": sources,
            "confidence": confidence
        }

    except Exception as e:
        print(f"[Tavily Error] {e}")
        return {
            "entity": query,
            "threat_context": f"Error performing threat intelligence search: {str(e)}",
            "sources": [],
            "confidence": 0.0
        }


def format_intel_for_agent(intel: Dict) -> str:
    """
    Format threat intelligence for agent consumption.

    Args:
        intel: Output from tavily_threat_search

    Returns:
        Formatted string for agent context
    """
    entity = intel.get("entity", "Unknown")
    context = intel.get("threat_context", "No context available")
    confidence = intel.get("confidence", 0.0)
    sources = intel.get("sources", [])

    formatted = f"[Threat Intel: {entity}]\n"
    formatted += f"{context}\n"

    if confidence > 0:
        formatted += f"Confidence: {confidence:.0%}\n"

    if sources:
        formatted += f"Sources: {', '.join(sources[:2])}\n"

    return formatted
