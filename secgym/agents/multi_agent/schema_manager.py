# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
SchemaManager - One-time schema discovery and semantic formatting.

Runs SHOW TABLES + DESCRIBE once per incident via the env's bare execute_query()
(which bypasses step counting), then formats the result into a semantic schema
block for injection into InvestigatorAgent's system prompt.
"""

from typing import Callable, Dict, List, Tuple, Any


# Tables to always DESCRIBE first — ordered by relevance to most incident types
PRIORITY_TABLES = [
    "SecurityAlert",
    "AlertEvidence",
    "SigninLogs",
    "OfficeActivity",
    "CloudAppEvents",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "BehaviorAnalytics",
    "ThreatIntelligenceIndicator",
    "SecurityIncident",
    "AADSignInLogs",
    "IdentityLogonEvents",
    "CloudAppSessionEvents",
    "AzureActivity",
    "DeviceFileEvents",
]

# Column name fragments → semantic category
_IP_FRAGMENTS     = {"ip", "remoteip", "localip", "sourceip", "destip", "address", "addr"}
_USER_FRAGMENTS   = {"user", "account", "upn", "email", "principal", "identity", "owner"}
_TIME_FRAGMENTS   = {"time", "date", "timestamp", "created", "generated", "occurred"}
_DEVICE_FRAGMENTS = {"device", "host", "computer", "machine", "endpoint", "hostname"}
_HASH_FRAGMENTS   = {"hash", "sha1", "sha256", "md5", "checksum"}
_FILE_FRAGMENTS   = {"file", "path", "folder", "process", "command", "cmd", "image"}


def _col_matches(col_name: str, fragments: set) -> bool:
    c = col_name.lower()
    return any(f in c for f in fragments)


class SchemaManager:
    """
    Discovers and caches the database schema for one incident.

    Usage:
        mgr = SchemaManager(execute_query_fn=thug_env.execute_query)
        schema_str = mgr.discover()          # run once per incident
        agent.load_schema(schema_str)        # inject into agent prompt
    """

    def __init__(self, execute_query_fn: Callable):
        """
        Args:
            execute_query_fn: Callable matching ExcytinEnv.execute_query signature.
                              Returns (results, success_bool).
        """
        self._exec = execute_query_fn
        self._schema_str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover(self) -> str:
        """
        Run schema discovery and return a formatted semantic schema string.
        Calls execute_query (not step()) so nothing is counted toward the
        agent's step budget or trajectory.
        """
        print("[SchemaManager] Starting schema discovery...")

        table_counts = self._get_table_counts()
        if not table_counts:
            print("[SchemaManager] Warning: Could not retrieve any tables.")
            return ""

        tables_to_describe = self._select_tables(table_counts)
        table_schemas = self._describe_tables(tables_to_describe)

        self._schema_str = self._format_schema(table_counts, table_schemas)
        print(f"[SchemaManager] Done. {len(table_counts)} tables found, "
              f"{len(table_schemas)} described.")
        return self._schema_str

    def get_prompt_block(self) -> str:
        return self._schema_str

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_table_counts(self) -> Dict[str, int]:
        """SHOW TABLES then COUNT(*) each one. Return {table_name: row_count}."""
        results, ok = self._exec("SHOW TABLES")
        if not ok or not results:
            return {}

        all_tables = [r[0] for r in results]
        counts = {}
        for table in all_tables:
            res, ok = self._exec(f"SELECT COUNT(*) FROM `{table}`")
            if ok and res:
                count = res[0][0]
                if count > 0:
                    counts[table] = count
        return counts

    def _select_tables(self, table_counts: Dict[str, int]) -> List[str]:
        """
        Pick up to 15 tables to DESCRIBE:
        priority list first (if they have data), then fill by row count.
        """
        selected = []
        for t in PRIORITY_TABLES:
            if t in table_counts:
                selected.append(t)

        # Fill remaining slots with highest-row-count tables not already selected
        remaining = sorted(
            (t for t in table_counts if t not in selected),
            key=lambda x: -table_counts[x]
        )
        for t in remaining:
            if len(selected) >= 15:
                break
            selected.append(t)

        return selected

    def _describe_tables(self, tables: List[str]) -> Dict[str, List[Tuple]]:
        """Run DESCRIBE on each table. Returns {table: [(col_name, type, ...), ...]}"""
        schemas = {}
        for table in tables:
            res, ok = self._exec(f"DESCRIBE `{table}`")
            if ok and res:
                schemas[table] = res
        return schemas

    def _format_schema(
        self,
        table_counts: Dict[str, int],
        table_schemas: Dict[str, List[Tuple]],
    ) -> str:
        """Build the semantic schema string injected into the agent prompt."""
        lines = [
            "=== DATABASE SCHEMA (pre-discovered — do NOT run SHOW TABLES or DESCRIBE) ===",
            "",
        ]

        # Tables with data summary
        tables_summary = ", ".join(
            f"{t} ({c:,} rows)"
            for t, c in sorted(table_counts.items(), key=lambda x: -x[1])
        )
        lines.append(f"Tables with data: {tables_summary}")
        lines.append("")

        # Semantic column groupings
        ip_cols, user_cols, time_cols, device_cols, hash_cols, file_cols = (
            [], [], [], [], [], []
        )
        for table, cols in table_schemas.items():
            for col in cols:
                name = col[0]
                full = f"{table}.{name}"
                if _col_matches(name, _IP_FRAGMENTS):
                    ip_cols.append(full)
                if _col_matches(name, _USER_FRAGMENTS):
                    user_cols.append(full)
                if _col_matches(name, _TIME_FRAGMENTS):
                    time_cols.append(full)
                if _col_matches(name, _DEVICE_FRAGMENTS):
                    device_cols.append(full)
                if _col_matches(name, _HASH_FRAGMENTS):
                    hash_cols.append(full)
                if _col_matches(name, _FILE_FRAGMENTS):
                    file_cols.append(full)

        if ip_cols:
            lines.append(f"IP address columns    : {', '.join(ip_cols[:14])}")
        if user_cols:
            lines.append(f"User/Account columns  : {', '.join(user_cols[:14])}")
        if time_cols:
            lines.append(f"Timestamp columns     : {', '.join(time_cols[:14])}")
        if device_cols:
            lines.append(f"Device/Host columns   : {', '.join(device_cols[:14])}")
        if hash_cols:
            lines.append(f"Hash columns          : {', '.join(hash_cols[:10])}")
        if file_cols:
            lines.append(f"File/Process columns  : {', '.join(file_cols[:14])}")

        lines.append("")
        lines.append("Key join paths:")
        lines.append("  SecurityAlert.SystemAlertId  = AlertEvidence.SystemAlertId")
        lines.append("  SigninLogs.UserPrincipalName  = OfficeActivity.UserId")
        lines.append("  AlertEvidence.DeviceName      = DeviceProcessEvents.DeviceName"
                     "  (always add Timestamp BETWEEN filter)")
        lines.append("")

        # Full column reference per table
        lines.append("=== FULL COLUMN REFERENCE ===")
        for table, cols in table_schemas.items():
            col_names = ", ".join(c[0] for c in cols)
            row_count = table_counts.get(table, "?")
            lines.append(f"{table} ({row_count:,} rows): {col_names}")

        return "\n".join(lines)
