"""
Authorization orchestrator.

Implements the flowchart in the action README top-to-bottom. Each stage is
a small function; the ``authorize`` coroutine wires them together and
produces an ``Outcome`` describing what happened.

Trust boundary reminder: this module ONLY makes decisions. It does not
execute PR-controlled code, does not check out the repository, does not
read from the runner filesystem. All external state is fetched through
``gh_api``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from githubkit import GitHub

from . import codeowners, gh_api
from .approvals import valid_approvals_at_head
from .trusted_bots import parse_ids


class OutcomeKind(str, Enum):
    """The possible authorization results.

    String-valued so log output and (if we ever add it as an action output)
    downstream consumption is human-readable.
    """

    AUTHORIZED_TRUSTED_BOT = "authorized_trusted_bot"
    AUTHORIZED_AUTHOR = "authorized_author"
    AUTHORIZED_APPROVAL = "authorized_approval"
    DENIED_UNSUPPORTED_EVENT = "denied_unsupported_event"
    DENIED_MISSING_PR = "denied_missing_pr"
    DENIED_MISSING_CODEOWNERS = "denied_missing_codeowners"
    DENIED_NO_TEAM_CODEOWNERS = "denied_no_team_codeowners"
    DENIED_NO_APPROVAL = "denied_no_approval"


@dataclass(frozen=True)
class Outcome:
    """The result of one authorization run."""

    kind: OutcomeKind
    # Human-readable message. For denials, this is what the caller
    # surfaces via ``core.setFailed`` — it should tell a maintainer
    # exactly what to do to unblock.
    message: str
    # If the event had a PR, this is its HEAD SHA. Always populated when
    # a PR was found in the event, even for denials — downstream jobs
    # depend on this output being set so they can pin their checkout.
    head_sha: str | None = None


ALLOWED_EVENTS: frozenset[str] = frozenset({"pull_request_target", "pull_request_review"})


async def authorize(
    gh: GitHub,
    *,
    event_name: str,
    event_payload: dict[str, Any],
    trusted_bot_ids_raw: str,
) -> Outcome:
    """Run the authorization gate for a single event.

    Args:
        gh: Authenticated GitHub client (installation token from a GitHub
            App with ``Members: Read`` and ``Contents: Read``).
        event_name: ``$GITHUB_EVENT_NAME`` value.
        event_payload: Parsed contents of ``$GITHUB_EVENT_PATH``.
        trusted_bot_ids_raw: Comma-separated numeric user IDs of always-authorized bots.

    Returns:
        An ``Outcome``. Callers translate this into GHA outputs and exit
        code via ``_actions``; no side effects happen inside this function.
    """
    # ── 1. Event-type gate ──────────────────────────────────────────
    if event_name not in ALLOWED_EVENTS:
        return Outcome(
            kind=OutcomeKind.DENIED_UNSUPPORTED_EVENT,
            message=(
                f"Unsupported event: {event_name!r}. "
                f"This action supports only: {sorted(ALLOWED_EVENTS)}."
            ),
        )

    pr = event_payload.get("pull_request")
    if not pr:
        return Outcome(
            kind=OutcomeKind.DENIED_MISSING_PR,
            message="Event payload has no `pull_request` object.",
        )

    author = pr["user"]
    author_login: str = author["login"]
    author_id: int = int(author["id"])
    author_type: str = author["type"]
    head_sha: str = pr["head"]["sha"]
    base_ref: str = pr["base"]["ref"]
    pr_number: int = int(pr["number"])

    # The repo we're gating comes from the base side of the PR, not the
    # head. Fork PRs have a different head repo; we always read teams,
    # CODEOWNERS, and reviews from the base repository.
    base_repo = pr["base"]["repo"]
    org: str = base_repo["owner"]["login"]
    repo_name: str = base_repo["name"]

    # ── 2. Trusted-bot fast path ────────────────────────────────────
    trusted_ids = parse_ids(trusted_bot_ids_raw)
    if author_id in trusted_ids and author_type == "Bot":
        return Outcome(
            kind=OutcomeKind.AUTHORIZED_TRUSTED_BOT,
            message=(f"Author {author_login!r} (id={author_id}) is a trusted bot."),
            head_sha=head_sha,
        )

    # ── 3. Fetch CODEOWNERS from base ref ───────────────────────────
    codeowners_file = await gh_api.fetch_codeowners(gh, owner=org, repo=repo_name, ref=base_ref)
    if codeowners_file is None:
        return Outcome(
            kind=OutcomeKind.DENIED_MISSING_CODEOWNERS,
            message=(
                f"No CODEOWNERS file found in base ref {base_ref!r} at any of "
                f"{list(gh_api.CODEOWNERS_LOCATIONS)}. "
                "This action requires a CODEOWNERS file with @org/team entries."
            ),
            head_sha=head_sha,
        )

    # ── 4. Parse CODEOWNERS ─────────────────────────────────────────
    parsed = codeowners.parse(codeowners_file.content, org)
    if not parsed.team_slugs:
        skipped_detail = _describe_skipped(parsed)
        return Outcome(
            kind=OutcomeKind.DENIED_NO_TEAM_CODEOWNERS,
            message=(
                f"CODEOWNERS at {codeowners_file.path}@{base_ref} has no "
                f"@{org}/<team> entries. "
                f"{skipped_detail}"
                "This action requires at least one team-scoped codeowner in the same org."
            ),
            head_sha=head_sha,
        )

    # ── 5. Author membership check ──────────────────────────────────
    author_membership = await gh_api.find_active_team_membership(
        gh, org=org, username=author_login, team_slugs=parsed.team_slugs
    )
    if author_membership is not None:
        return Outcome(
            kind=OutcomeKind.AUTHORIZED_AUTHOR,
            message=(
                f"PR author {author_login!r} is an active member of "
                f"@{org}/{author_membership.team_slug} "
                f"(role={author_membership.role})."
            ),
            head_sha=head_sha,
        )

    # ── 6. Approval check ───────────────────────────────────────────
    all_reviews = await gh_api.list_pr_reviews(gh, owner=org, repo=repo_name, pull_number=pr_number)
    candidates = valid_approvals_at_head(all_reviews, head_sha, author_login)
    for approval in candidates:
        membership = await gh_api.find_active_team_membership(
            gh, org=org, username=approval.reviewer_login, team_slugs=parsed.team_slugs
        )
        if membership is not None:
            return Outcome(
                kind=OutcomeKind.AUTHORIZED_APPROVAL,
                message=(
                    f"PR approved by codeowner {approval.reviewer_login!r} "
                    f"(team=@{org}/{membership.team_slug}) at {head_sha}."
                ),
                head_sha=head_sha,
            )

    approver_summary = ", ".join(a.reviewer_login for a in candidates) if candidates else "(none)"
    teams_summary = ", ".join(f"@{org}/{t}" for t in parsed.team_slugs)
    return Outcome(
        kind=OutcomeKind.DENIED_NO_APPROVAL,
        message=(
            f"PR author {author_login!r} is not a codeowner. "
            f"Approvals at HEAD {head_sha} came from: {approver_summary}. "
            f"None of them are active members of a codeowner team [{teams_summary}]. "
            "A codeowner must submit an APPROVE review on the current commit."
        ),
        head_sha=head_sha,
    )


def _describe_skipped(parsed: codeowners.ParseResult) -> str:
    """Format a helpful diagnostic listing owners the parser dropped.

    Used when no team codeowners were found — the maintainer needs to
    know whether they wrote emails, individual handles, or cross-org
    teams so they can migrate.
    """
    parts: list[str] = []
    if parsed.individuals:
        parts.append(
            f"Ignored {len(parsed.individuals)} individual handle(s): "
            f"{', '.join(parsed.individuals)}."
        )
    if parsed.emails:
        parts.append(f"Ignored {len(parsed.emails)} email owner(s): {', '.join(parsed.emails)}.")
    if parsed.cross_org_teams:
        parts.append(
            f"Ignored {len(parsed.cross_org_teams)} cross-org team(s): "
            f"{', '.join(parsed.cross_org_teams)}."
        )
    if not parts:
        return ""
    return " ".join(parts) + " "
