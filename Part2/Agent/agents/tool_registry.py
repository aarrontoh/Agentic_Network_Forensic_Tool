"""
Deterministic tool registry for the multi-agent system.

Every tool that an agent can call is registered here.  Tools are the ONLY way
agents can access evidence — they cannot fabricate data.  This is the core
guardrail: if a finding isn't backed by a tool result, it's hallucination.

Tools available to worker agents
--------------------------------
  query_db        – Execute a read-only SQL query against the forensic database.
  count_rows      – Quick row count with optional WHERE clause.
  get_table_info  – List columns and sample rows for a table.
  summarize_db    – Return row counts for all evidence tables.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional

# Maximum rows returned per query to stay within LLM context limits
_MAX_ROWS = 200


# ──────────────────────────────────────────────────────────────────────────────
# Tool implementations
# ──────────────────────────────────────────────────────────────────────────────

def query_db(conn: sqlite3.Connection, sql: str, params: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Execute a read-only SQL SELECT against the forensic database.

    Returns {"columns": [...], "rows": [[...], ...], "row_count": int, "truncated": bool}.
    Only SELECT statements are allowed — any write attempt is rejected.
    """
    sql_stripped = sql.strip().rstrip(";")
    sql_upper = sql_stripped.upper()

    # Guardrail: block any non-SELECT statement
    if not sql_upper.startswith("SELECT"):
        return {"error": "Only SELECT queries are allowed. The database is read-only for agents."}

    # Block dangerous patterns — strip string literals first so values like
    # 'delete.me' don't false-positive on the DELETE keyword
    import re
    sql_no_strings = re.sub(r"'[^']*'", "", sql_upper)  # remove 'quoted values'
    sql_no_strings = re.sub(r'"[^"]*"', "", sql_no_strings)  # remove "quoted values"
    for blocked in ("DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE", "ATTACH", "DETACH"):
        # Check as whole word to avoid false positives
        if re.search(r'\b' + blocked + r'\b', sql_no_strings):
            return {"error": f"Blocked keyword '{blocked}' detected. Only read-only SELECT queries are permitted."}

    try:
        cursor = conn.execute(sql_stripped, params or [])
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = cursor.fetchmany(_MAX_ROWS + 1)
        truncated = len(rows) > _MAX_ROWS
        if truncated:
            rows = rows[:_MAX_ROWS]
        return {
            "columns": columns,
            "rows": [list(row) for row in rows],
            "row_count": len(rows),
            "truncated": truncated,
        }
    except Exception as e:
        return {"error": f"SQL error: {str(e)}"}


def count_rows(conn: sqlite3.Connection, table: str, where: str = "") -> Dict[str, Any]:
    """Count rows in a table with optional WHERE clause."""
    allowed_tables = {
        "alerts", "zeek_conn", "zeek_dns", "zeek_ssl", "zeek_http",
        "zeek_dce_rpc", "zeek_rdp", "zeek_smb",
        "pcap_dns", "pcap_http", "pcap_tls", "pcap_smb", "pcap_rdp", "pcap_tcp_conv", "pcap_tcp_conv",
    }
    if table not in allowed_tables:
        return {"error": f"Unknown table '{table}'. Allowed: {sorted(allowed_tables)}"}

    if where:
        # Block write-like keywords to prevent SQL injection
        _blocked = {"insert", "update", "delete", "drop", "alter", "create", "attach", "detach"}
        if any(kw in where.lower().split() for kw in _blocked):
            return {"error": "WHERE clause contains disallowed keyword."}
    sql = f"SELECT COUNT(*) FROM {table}"
    if where:
        sql += f" WHERE {where}"
    try:
        row = conn.execute(sql).fetchone()
        return {"table": table, "where": where or "(none)", "count": row[0]}
    except Exception as e:
        return {"error": f"SQL error: {str(e)}"}


def get_table_info(conn: sqlite3.Connection, table: str, sample_limit: int = 5) -> Dict[str, Any]:
    """Return column names and a few sample rows for a table."""
    allowed_tables = {
        "alerts", "zeek_conn", "zeek_dns", "zeek_ssl", "zeek_http",
        "zeek_dce_rpc", "zeek_rdp", "zeek_smb",
        "pcap_dns", "pcap_http", "pcap_tls", "pcap_smb", "pcap_rdp", "pcap_tcp_conv", "pcap_tcp_conv",
    }
    if table not in allowed_tables:
        return {"error": f"Unknown table '{table}'."}
    try:
        cursor = conn.execute(f"SELECT * FROM {table} LIMIT {min(sample_limit, 10)}")
        columns = [desc[0] for desc in cursor.description]
        rows = [list(row) for row in cursor.fetchall()]
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return {"table": table, "columns": columns, "sample_rows": rows, "total_rows": count}
    except Exception as e:
        return {"error": str(e)}


def summarize_db(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Return row counts for all evidence tables."""
    from db.schema import get_table_stats
    return {"table_counts": get_table_stats(conn)}


# ──────────────────────────────────────────────────────────────────────────────
# Gemini function declarations (for function-calling API)
# ──────────────────────────────────────────────────────────────────────────────

TOOL_DECLARATIONS = [
    {
        "name": "query_db",
        "description": (
            "Execute a read-only SQL SELECT query against the forensic evidence database. "
            "The database contains tables: alerts, zeek_conn, zeek_dns, zeek_ssl, zeek_http, "
            "zeek_dce_rpc, zeek_rdp, zeek_smb, pcap_dns, pcap_http, pcap_tls, pcap_smb, pcap_rdp, pcap_tcp_conv. "
            "Returns columns, rows (max 200), and whether results were truncated. "
            "Use this to find specific evidence, correlate IPs, and validate hypotheses. "
            "IMPORTANT: You MUST use this tool to support any claim with real data."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "A SQL SELECT query. Only SELECT is allowed. Use LIMIT to control result size.",
                },
            },
            "required": ["sql"],
        },
    },
    {
        "name": "count_rows",
        "description": (
            "Quick count of rows in an evidence table, with optional WHERE filter. "
            "Faster than query_db for simple counts."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Table name (e.g., 'alerts', 'zeek_conn', 'pcap_tls').",
                },
                "where": {
                    "type": "string",
                    "description": "Optional WHERE clause without the 'WHERE' keyword (e.g., \"src_ip = '10.1.1.1'\").",
                },
            },
            "required": ["table"],
        },
    },
    {
        "name": "get_table_info",
        "description": (
            "Inspect a table's columns and see a few sample rows. "
            "Use this first to understand the data schema before writing queries."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Table name to inspect.",
                },
            },
            "required": ["table"],
        },
    },
    {
        "name": "summarize_db",
        "description": "Get row counts for all evidence tables. Use this to understand what data is available.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
]


def dispatch_tool(conn: sqlite3.Connection, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Route a tool call to the appropriate function."""
    if tool_name == "query_db":
        return query_db(conn, args.get("sql", ""))
    elif tool_name == "count_rows":
        return count_rows(conn, args.get("table", ""), args.get("where", ""))
    elif tool_name == "get_table_info":
        return get_table_info(conn, args.get("table", ""))
    elif tool_name == "summarize_db":
        return summarize_db(conn)
    else:
        return {"error": f"Unknown tool: {tool_name}"}
