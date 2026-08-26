"""DB-backed rule store: L2's "DB-backed RBAC tool registry" (Section 13).

Same five-layer permission hierarchy as the L1 YAML ruleset and the
document's own OPA Rego reference (Section 15.1/15.2), but persisted in
SQLite so a security team can update rules live (INSERT/UPDATE/DELETE)
without a code deploy - the actual point of moving policy out of static
config. DbBackedPolicyEngine and DbBackedToolRegistry share this one
read/write surface so their view of the world can never drift apart.

SQLite (stdlib) is used rather than a client/server DB so this tier still
requires no external account or running service; swapping to Postgres/etc.
at L3 only touches this module's connection handling, not its callers.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS roles (
    role_name TEXT PRIMARY KEY,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tools (
    tool_name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS tool_visibility_roles (
    tool_name TEXT NOT NULL,
    role_name TEXT NOT NULL,
    PRIMARY KEY (tool_name, role_name)
);

CREATE TABLE IF NOT EXISTS tool_functions (
    tool_name TEXT NOT NULL,
    function_name TEXT NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tool_name, function_name)
);

CREATE TABLE IF NOT EXISTS parameter_deny_patterns (
    tool_name TEXT NOT NULL,
    param_name TEXT NOT NULL,
    pattern TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS parameter_role_gates (
    tool_name TEXT NOT NULL,
    param_name TEXT NOT NULL,
    param_value TEXT NOT NULL,
    required_role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

DEFAULT_RATE_LIMIT = 50
DEFAULT_IDENTITY_FIELDS = ["user_id", "agent_id", "roles"]


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (creating if needed) a rule-store database with schema applied."""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def seed_example(conn: sqlite3.Connection) -> None:
    """Seed the same example rules as configs/policy.example.yaml, for parity."""
    conn.executescript(
        """
        DELETE FROM roles; DELETE FROM tools; DELETE FROM tool_visibility_roles;
        DELETE FROM tool_functions; DELETE FROM parameter_deny_patterns;
        DELETE FROM parameter_role_gates; DELETE FROM settings;
        """
    )
    roles = ["AgentExecutor", "DeployEngineer", "ProductionAdmin"]
    conn.executemany("INSERT INTO roles (role_name, active) VALUES (?, 1)", [(r,) for r in roles])

    tools = ["search_tool", "sql_tool", "deploy_tool"]
    conn.executemany("INSERT INTO tools (tool_name) VALUES (?)", [(t,) for t in tools])

    conn.executemany(
        "INSERT INTO tool_functions (tool_name, function_name, requires_approval) VALUES (?, ?, ?)",
        [
            ("search_tool", "query", 0),
            ("sql_tool", "ExecuteReadOnlyQuery", 0),
            ("sql_tool", "UpdateCustomerRecord", 0),
            ("deploy_tool", "deploy", 1),
        ],
    )

    conn.executemany(
        "INSERT INTO tool_visibility_roles (tool_name, role_name) VALUES (?, ?)",
        [("deploy_tool", "DeployEngineer"), ("deploy_tool", "ProductionAdmin")],
    )

    conn.execute(
        "INSERT INTO parameter_deny_patterns (tool_name, param_name, pattern) VALUES (?, ?, ?)",
        ("sql_tool", "query", r"(?i)(DROP|DELETE|TRUNCATE|ALTER)"),
    )

    conn.execute(
        "INSERT INTO parameter_role_gates "
        "(tool_name, param_name, param_value, required_role) VALUES (?, ?, ?, ?)",
        ("deploy_tool", "environment", "production", "ProductionAdmin"),
    )

    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('rate_limit_per_session', ?)",
        (str(DEFAULT_RATE_LIMIT),),
    )
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('identity_required_fields', ?)",
        (",".join(DEFAULT_IDENTITY_FIELDS),),
    )
    conn.commit()


class DbRuleStore:
    """Typed read surface over the rule-store schema, shared by engine and registry."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def active_roles(self) -> set[str]:
        rows = self._conn.execute("SELECT role_name FROM roles WHERE active = 1").fetchall()
        return {row["role_name"] for row in rows}

    def tool_exists(self, tool_name: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM tools WHERE tool_name = ?", (tool_name,)
        ).fetchone()
        return row is not None

    def tool_names(self) -> list[str]:
        rows = self._conn.execute("SELECT tool_name FROM tools").fetchall()
        return [row["tool_name"] for row in rows]

    def visibility_roles(self, tool_name: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT role_name FROM tool_visibility_roles WHERE tool_name = ?", (tool_name,)
        ).fetchall()
        return [row["role_name"] for row in rows]

    def allowed_functions(self, tool_name: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT function_name FROM tool_functions WHERE tool_name = ?", (tool_name,)
        ).fetchall()
        return [row["function_name"] for row in rows]

    def requires_approval(self, tool_name: str, function_name: str) -> bool:
        row = self._conn.execute(
            "SELECT requires_approval FROM tool_functions "
            "WHERE tool_name = ? AND function_name = ?",
            (tool_name, function_name),
        ).fetchone()
        return bool(row["requires_approval"]) if row else False

    def deny_patterns(self, tool_name: str) -> dict[str, list[str]]:
        rows = self._conn.execute(
            "SELECT param_name, pattern FROM parameter_deny_patterns WHERE tool_name = ?",
            (tool_name,),
        ).fetchall()
        result: dict[str, list[str]] = {}
        for row in rows:
            result.setdefault(row["param_name"], []).append(row["pattern"])
        return result

    def role_gates(self, tool_name: str) -> dict[str, list[str]]:
        rows = self._conn.execute(
            "SELECT param_name, param_value, required_role FROM parameter_role_gates "
            "WHERE tool_name = ?",
            (tool_name,),
        ).fetchall()
        result: dict[str, list[str]] = {}
        for row in rows:
            key = f"{row['param_name']}={row['param_value']}"
            result.setdefault(key, []).append(row["required_role"])
        return result

    def rate_limit_per_session(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = 'rate_limit_per_session'"
        ).fetchone()
        return int(row["value"]) if row else DEFAULT_RATE_LIMIT

    def identity_required_fields(self) -> list[str]:
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = 'identity_required_fields'"
        ).fetchone()
        return row["value"].split(",") if row else list(DEFAULT_IDENTITY_FIELDS)
