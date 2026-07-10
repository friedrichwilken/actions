"""
CODEOWNERS parser.

Extracts ``@<org>/<team>`` entries from CODEOWNERS text. Individual GitHub
handles, email addresses, and teams from other orgs are recorded as
"unsupported" so the caller can surface them in diagnostics — the action
requires team entries in the same org as the repository.

CODEOWNERS syntax reference:
<https://docs.github.com/articles/about-code-owners>

Notable syntax handled here:
- Full-line comments: ``# comment``
- Inline comments: ``pattern @owner  # comment``
- Section headers: ``[section-name]`` and ``^[section-name]`` (approvals-optional)
- Section headers with default owners: ``[section] @default-owner``
- Whitespace: tabs and spaces are equivalent as separators
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ``[section]`` and ``^[section]`` at the start of a line (after optional
# whitespace) is a section header, not a file pattern. GitHub introduced
# section syntax in 2022 for CODEOWNERS files that live in
# ``.github/CODEOWNERS`` and are used with branch protection.
#
# The trailing lookahead requires the closing ``]`` to be followed by
# whitespace or end-of-line, so a glob character class like
# ``[Cc]hangelog.md`` (which starts with ``[Cc]`` immediately followed by
# ``hangelog.md``, no whitespace between) is NOT mistaken for a header.
# Without this lookahead, ``[Cc]hangelog.md @acme/docs-team`` would strip
# the ``[Cc]`` prefix and then parse ``hangelog.md @acme/docs-team`` as a
# section header with a default owner — silently granting the team
# whole-repo authorization.
_SECTION_HEADER = re.compile(r"^\s*\^?\[[^\]]+\](?=\s|$)")

# A team owner: @<org>/<team-slug>. Slugs are lowercase alphanumerics and
# hyphens; we don't validate slug format here — GitHub's own parser is more
# permissive and we prefer to accept anything that looks team-shaped than
# invent a rejection rule.
_TEAM_OWNER = re.compile(r"^@([^/\s]+)/([^/\s]+)$")

# An individual owner: @<user>. No slash.
_INDIVIDUAL_OWNER = re.compile(r"^@[^/\s]+$")

# Rough email check. Owners can be email addresses that map to a GitHub user
# via the user's public commit email. We identify these but don't process
# them — this action requires team entries.
_EMAIL_OWNER = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


@dataclass(frozen=True)
class ParseResult:
    """Result of parsing a CODEOWNERS file for a given org.

    Attributes:
        team_slugs: Team slugs (without ``@org/`` prefix) that match the
            configured org. Ordered by first appearance in the file.
        individuals: ``@user`` handles the parser saw and skipped.
        emails: Email-address owners the parser saw and skipped.
        cross_org_teams: ``@other-org/team`` entries the parser saw and skipped.
    """

    team_slugs: tuple[str, ...]
    individuals: tuple[str, ...] = field(default_factory=tuple)
    emails: tuple[str, ...] = field(default_factory=tuple)
    cross_org_teams: tuple[str, ...] = field(default_factory=tuple)


def parse(text: str, org: str) -> ParseResult:
    """Parse CODEOWNERS text and return the entries for ``org``.

    Args:
        text: Raw CODEOWNERS file contents.
        org: GitHub organization slug (case-insensitive comparison).

    Returns:
        A ``ParseResult``. Fields preserve source order; duplicates removed.
    """
    org_lower = org.lower()

    seen_teams: dict[str, None] = {}
    seen_individuals: dict[str, None] = {}
    seen_emails: dict[str, None] = {}
    seen_cross_org: dict[str, None] = {}

    for raw_line in text.splitlines():
        # Strip inline comments. A ``#`` inside quotes would be a CODEOWNERS
        # syntax error anyway; treat any ``#`` as start-of-comment.
        line = raw_line.split("#", 1)[0]
        # Detect and strip a leading section header. When a header is
        # present, the remaining tokens are default-owners for the
        # section (no file pattern precedes them). When absent, the
        # first token is the file pattern and the rest are owners.
        section_match = _SECTION_HEADER.match(line)
        if section_match:
            line = line[section_match.end() :]
            line = line.strip()
            if not line:
                continue
            owners = line.split()
        else:
            line = line.strip()
            if not line:
                continue
            tokens = line.split()
            # First token is the file pattern; owners follow.
            owners = tokens[1:] if len(tokens) > 1 else []

        for owner in owners:
            team_match = _TEAM_OWNER.match(owner)
            if team_match:
                owner_org, owner_slug = team_match.group(1), team_match.group(2)
                if owner_org.lower() == org_lower:
                    # GitHub team slugs are always lowercase. Normalize here
                    # so an uppercase CODEOWNERS entry (@org/Team-A) resolves
                    # to the real slug (team-a) instead of 404-ing the teams
                    # API and denying a legitimate codeowner — and so it
                    # dedups against a lowercase spelling of the same team.
                    seen_teams.setdefault(owner_slug.lower(), None)
                else:
                    seen_cross_org.setdefault(owner, None)
                continue
            if _INDIVIDUAL_OWNER.match(owner):
                seen_individuals.setdefault(owner, None)
                continue
            if _EMAIL_OWNER.match(owner):
                seen_emails.setdefault(owner, None)
                continue
            # Silently ignore anything else — CODEOWNERS pattern lines can
            # have trailing garbage in the wild and we don't want to fail
            # hard on unrecognized owner formats.

    return ParseResult(
        team_slugs=tuple(seen_teams),
        individuals=tuple(seen_individuals),
        emails=tuple(seen_emails),
        cross_org_teams=tuple(seen_cross_org),
    )
