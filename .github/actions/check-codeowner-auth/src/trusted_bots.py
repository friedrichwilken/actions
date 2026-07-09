"""
Trusted-bot allowlist parsing.

The allowlist is keyed by numeric GitHub user ID, not by login. Logins can
be recreated after deletion; user IDs are stable. At authorization time we
additionally verify ``user.type == 'Bot'`` — an attacker who somehow
registers an account with a matching login would still be classified
``User`` and rejected.
"""

from __future__ import annotations


def parse_ids(raw: str) -> frozenset[int]:
    """Parse a comma-separated list of numeric user IDs.

    Whitespace around commas and empty entries are ignored. Non-numeric
    entries are silently dropped — the input comes from workflow YAML,
    which is user-editable, and we prefer "your bot won't be trusted"
    over "your workflow crashes."

    Args:
        raw: Comma-separated string. Empty string is treated as "no IDs".

    Returns:
        Immutable set of parsed IDs.
    """
    ids: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            ids.add(int(token))
        except ValueError:
            # Silently skip. See docstring.
            continue
    return frozenset(ids)
