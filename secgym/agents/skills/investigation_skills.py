# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Investigation Skills - SQL optimization, entity extraction, timeline building
"""

import re
from typing import Dict, List, Tuple, Any
from datetime import datetime


def extract_entities(text: str) -> Dict[str, List[str]]:
    """
    Extract security-relevant entities from text using regex patterns.

    Args:
        text: Text to extract entities from (SQL results, logs, etc.)

    Returns:
        Dictionary with entity types as keys:
        {
            "ips": [...],
            "users": [...],
            "hosts": [...],
            "hashes": [...],
            "domains": [...],
            "emails": [...]
        }
    """
    entities = {
        "ips": [],
        "users": [],
        "hosts": [],
        "hashes": [],
        "domains": [],
        "emails": []
    }

    # IP addresses (IPv4 only for now)
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    entities["ips"] = list(set(re.findall(ip_pattern, text)))

    # Email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    entities["emails"] = list(set(re.findall(email_pattern, text)))

    # Domain names (basic pattern)
    domain_pattern = r'\b[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}\b'
    domains = re.findall(domain_pattern, text.lower())
    # Filter out common false positives
    entities["domains"] = list(set([d for d in domains if d not in entities["emails"]]))

    # File hashes (MD5: 32 hex, SHA256: 64 hex)
    hash_pattern = r'\b[a-f0-9]{32}(?:[a-f0-9]{32})?\b'
    entities["hashes"] = list(set(re.findall(hash_pattern, text.lower())))

    # Usernames (common patterns)
    # Look for user= or username= or AccountName or similar
    user_patterns = [
        r'user(?:name)?[=:\s]+([A-Za-z0-9@._-]+)',
        r'account(?:name)?[=:\s]+([A-Za-z0-9@._-]+)',
        r'\\([A-Za-z0-9._-]+)(?:\s|$)',  # Domain\username
    ]
    for pattern in user_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        entities["users"].extend(matches)
    entities["users"] = list(set(entities["users"]))

    # Hostnames (common patterns)
    host_patterns = [
        r'host(?:name)?[=:\s]+([A-Za-z0-9._-]+)',
        r'device(?:name)?[=:\s]+([A-Za-z0-9._-]+)',
        r'computer(?:name)?[=:\s]+([A-Za-z0-9._-]+)',
    ]
    for pattern in host_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        entities["hosts"].extend(matches)
    entities["hosts"] = list(set(entities["hosts"]))

    # Remove empty lists
    entities = {k: v for k, v in entities.items() if v}

    return entities


def build_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sort events chronologically and group by entity.

    Args:
        events: List of event dictionaries, each should have a timestamp field

    Returns:
        Sorted list of events with additional context
    """
    if not events:
        return []

    # Try to find timestamp field (common names)
    timestamp_fields = ['timestamp', 'Timestamp', 'TimeGenerated', 'time', 'datetime',
                       'CreatedDateTime', 'ActivityDateTime', 'EventTime']

    # Identify which field to use
    timestamp_field = None
    if events and isinstance(events[0], dict):
        for field in timestamp_fields:
            if field in events[0]:
                timestamp_field = field
                break

    if not timestamp_field:
        # Can't sort without timestamp
        print("[Timeline] Warning: No timestamp field found in events")
        return events

    # Sort by timestamp
    try:
        sorted_events = sorted(events, key=lambda x: x.get(timestamp_field, ''))
    except Exception as e:
        print(f"[Timeline] Error sorting events: {e}")
        return events

    # Add sequence numbers
    for idx, event in enumerate(sorted_events):
        event['_sequence'] = idx + 1

    return sorted_events


def optimize_query(sql: str, max_rows: int = 100) -> str:
    """
    Optimize SQL query to prevent overwhelming context window.

    Optimizations:
    1. Add LIMIT clause if missing
    2. Basic syntax validation
    3. Warn about expensive operations

    Args:
        sql: SQL query string
        max_rows: Maximum rows to return (default 100)

    Returns:
        Optimized SQL string
    """
    sql = sql.strip()

    # Remove trailing semicolon
    if sql.endswith(';'):
        sql = sql[:-1]

    # Check if LIMIT already exists
    has_limit = re.search(r'\bLIMIT\s+\d+', sql, re.IGNORECASE)

    if not has_limit:
        # Add LIMIT clause
        sql = f"{sql} LIMIT {max_rows}"
        print(f"[QueryOptimizer] Added LIMIT {max_rows} to query")

    # Basic validation
    sql_upper = sql.upper()

    # Warn about potentially expensive operations
    if 'SELECT *' in sql_upper:
        print("[QueryOptimizer] Warning: SELECT * can return large results. Consider specifying columns.")

    if 'JOIN' in sql_upper and 'WHERE' not in sql_upper:
        print("[QueryOptimizer] Warning: JOIN without WHERE clause may be slow.")

    # Check for dangerous operations (should not happen, but safety check)
    dangerous_keywords = ['DROP', 'DELETE', 'TRUNCATE', 'UPDATE', 'INSERT', 'ALTER']
    for keyword in dangerous_keywords:
        if keyword in sql_upper:
            print(f"[QueryOptimizer] ERROR: Dangerous operation detected: {keyword}")
            raise ValueError(f"Query contains dangerous keyword: {keyword}")

    return sql


def paginate_results(results: List[Any], max_rows: int = 15, max_str_len: int = 100000) -> Tuple[List[Any], str]:
    """
    Paginate and truncate SQL results to manage context size.

    Args:
        results: List of query results
        max_rows: Maximum number of rows to keep
        max_str_len: Maximum string length for entire result

    Returns:
        Tuple of (truncated_results, summary_message)
    """
    original_count = len(results)

    # Limit rows
    if original_count > max_rows:
        results = results[:max_rows]
        summary = f"Showing {max_rows} of {original_count} rows (truncated)"
    else:
        summary = f"Showing all {original_count} rows"

    # Convert to string and check length
    results_str = str(results)
    if len(results_str) > max_str_len:
        # Further truncate
        results_str = results_str[:max_str_len]
        summary += f" | String truncated to {max_str_len} chars"

    return results, summary
