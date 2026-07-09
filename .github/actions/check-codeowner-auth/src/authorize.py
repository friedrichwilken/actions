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

import httpx
from githubkit import GitHub
from githubkit.exception import RequestError, RequestFailed

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
    DENIED_MALFORMED_PAYLOAD = "denied_malformed_payload"
    DENIED_MISSING_CODEOWNERS = "denied_missing_codeowners"
    DENIED_NO_TEAM_CODEOWNERS = "denied_no_team_codeowners"
    DENIED_NO_APPROVAL = "denied_no_approval"
    DENIED_API_ERROR = "denied_api_error"


@dataclass(frozen=True)
class Outcome:
    """The result of one authorization run."""

    kind: OutcomeKind
    # Human-readable message. For denials, this is what the caller
    # surfaces via ``core.setFailed`` — it should tell a maintainer
    # exactly what to do to unblock.
    message: str
    # If the event had a PR whose shape was valid enough to extract
    # ``head.sha``, this is that SHA. Set even for denials from stages
    # AFTER payload extraction — downstream jobs pin their
    # ``actions/checkout`` to this output so a mid-run force-push cannot
    # slip untrusted code through. Absent for the two pre-extraction
    # failure modes (``DENIED_UNSUPPORTED_EVENT``, ``DENIED_MISSING_PR``,
    # ``DENIED_MALFORMED_PAYLOAD``) — there's no vetted SHA to emit.
    head_sha: str | None = None


ALLOWED_EVENTS: frozenset[str] = frozenset({"pull_request_target", "pull_request_review"})


@dataclass(frozen=True)
class _PRContext:
    """The subset of the event payload the orchestrator actually uses.

    Extracting into a validated dataclass lets us confine every payload
    KeyError / TypeError / ValueError to one place (``_extract_pr_context``)
    and translate them into a clean ``DENIED_MALFORMED_PAYLOAD`` outcome.
    Without this, any schema change in the GitHub webhook payload — or a
    replayed / hand-crafted event — would produce an uncaught traceback
    instead of the documented outcome contract.
    """

    author_login: str
    author_id: int
    author_type: str
    head_sha: str
    base_ref: str
    org: str
    repo_name: str
    pr_number: int


class _PayloadError(Exception):
    """Raised by ``_extract_pr_context`` when a required field is missing or malformed."""


def _extract_pr_context(pr: Any) -> _PRContext:
    """Pull the required fields out of the event ``pull_request`` object.

    Any missing / wrong-typed field raises ``_PayloadError`` with a
    diagnostic pointing at the offending path. The caller catches it and
    returns a ``DENIED_MALFORMED_PAYLOAD`` outcome.

    All payload access lives here; nothing in the main orchestrator body
    accesses ``pr[...]`` directly.
    """
    try:
        author = pr["user"]
        author_login = str(author["login"])
        author_id = int(author["id"])
        author_type = str(author["type"])
        head_sha = str(pr["head"]["sha"])
        base_ref = str(pr["base"]["ref"])
        pr_number = int(pr["number"])
        base_repo = pr["base"]["repo"]
        org = str(base_repo["owner"]["login"])
        repo_name = str(base_repo["name"])
    except (KeyError, TypeError, ValueError) as e:
        raise _PayloadError(f"Malformed pull_request payload: {e}") from e
    return _PRContext(
        author_login=author_login,
        author_id=author_id,
        author_type=author_type,
        head_sha=head_sha,
        base_ref=base_ref,
        org=org,
        repo_name=repo_name,
        pr_number=pr_number,
    )


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

    # ── 2. Extract & validate payload shape ─────────────────────────
    try:
        ctx = _extract_pr_context(pr)
    except _PayloadError as e:
        # No head_sha available — the extract step is exactly where we
        # would have got it, and it failed. Downstream jobs pinning to
        # ``needs.authorize.outputs.head-sha`` will see empty; that's
        # correct because there's no vetted SHA to hand out.
        return Outcome(
            kind=OutcomeKind.DENIED_MALFORMED_PAYLOAD,
            message=(
                f"{e} Reject via fail-closed; the pull_request payload does not have "
                f"the shape this action requires."
            ),
        )

    # ── 3. Trusted-bot fast path ────────────────────────────────────
    trusted_ids = parse_ids(trusted_bot_ids_raw)
    if ctx.author_id in trusted_ids and ctx.author_type == "Bot":
        return Outcome(
            kind=OutcomeKind.AUTHORIZED_TRUSTED_BOT,
            message=(f"Author {ctx.author_login!r} (id={ctx.author_id}) is a trusted bot."),
            head_sha=ctx.head_sha,
        )

    # ── 4. Network stages (CODEOWNERS + team membership + reviews) ──
    # Everything from here on hits the GitHub API. Transient failures
    # (5xx, secondary rate limits, connection resets) or App-token scope
    # misconfig used to escape as uncaught tracebacks, breaking the
    # ``head_sha`` output contract. Wrap once at the boundary so any such
    # failure produces a clean ``DENIED_API_ERROR`` with ``head_sha``
    # populated for downstream pinning.
    try:
        return await _authorize_with_api(gh, ctx)
    except RequestFailed as e:
        status = e.response.status_code
        return Outcome(
            kind=OutcomeKind.DENIED_API_ERROR,
            message=(
                f"GitHub API returned unexpected status {status} during authorization. "
                f"Common causes: transient 5xx, secondary rate limit (403/429), or the "
                f"App-token's permissions are misconfigured (needs Members: Read and "
                f"Contents: Read). Failing closed."
            ),
            head_sha=ctx.head_sha,
        )
    except (RequestError, httpx.HTTPError, TimeoutError) as e:
        # Transport-level: DNS, TLS, connection reset, read timeout, and
        # githubkit's own transport wrappers (``RequestError`` /
        # ``RequestTimeout``, both of which wrap the underlying httpx
        # exceptions before they reach us).
        return Outcome(
            kind=OutcomeKind.DENIED_API_ERROR,
            message=(
                f"Transport error contacting the GitHub API ({type(e).__name__}: {e}). "
                f"Failing closed. Rerun the workflow to retry."
            ),
            head_sha=ctx.head_sha,
        )


async def _authorize_with_api(gh: GitHub, ctx: _PRContext) -> Outcome:
    """Run the network-touching authorization stages against ``ctx``.

    Split out so the caller can wrap the whole thing in one try/except
    without cluttering the orchestrator with error-handling per call.
    """
    # ── Fetch CODEOWNERS from base ref ──────────────────────────────
    codeowners_file = await gh_api.fetch_codeowners(
        gh, owner=ctx.org, repo=ctx.repo_name, ref=ctx.base_ref
    )
    if codeowners_file is None:
        return Outcome(
            kind=OutcomeKind.DENIED_MISSING_CODEOWNERS,
            message=(
                f"No CODEOWNERS file found in base ref {ctx.base_ref!r} at any of "
                f"{list(gh_api.CODEOWNERS_LOCATIONS)}. "
                "This action requires a CODEOWNERS file with @org/team entries."
            ),
            head_sha=ctx.head_sha,
        )

    # ── Parse CODEOWNERS ────────────────────────────────────────────
    parsed = codeowners.parse(codeowners_file.content, ctx.org)
    if not parsed.team_slugs:
        skipped_detail = _describe_skipped(parsed)
        return Outcome(
            kind=OutcomeKind.DENIED_NO_TEAM_CODEOWNERS,
            message=(
                f"CODEOWNERS at {codeowners_file.path}@{ctx.base_ref} has no "
                f"@{ctx.org}/<team> entries. "
                f"{skipped_detail}"
                "This action requires at least one team-scoped codeowner in the same org."
            ),
            head_sha=ctx.head_sha,
        )

    # ── Author membership check ─────────────────────────────────────
    author_membership = await gh_api.find_active_team_membership(
        gh, org=ctx.org, username=ctx.author_login, team_slugs=parsed.team_slugs
    )
    if author_membership is not None:
        return Outcome(
            kind=OutcomeKind.AUTHORIZED_AUTHOR,
            message=(
                f"PR author {ctx.author_login!r} is an active member of "
                f"@{ctx.org}/{author_membership.team_slug} "
                f"(role={author_membership.role})."
            ),
            head_sha=ctx.head_sha,
        )

    # ── Approval check ──────────────────────────────────────────────
    all_reviews = await gh_api.list_pr_reviews(
        gh, owner=ctx.org, repo=ctx.repo_name, pull_number=ctx.pr_number
    )
    candidates = valid_approvals_at_head(all_reviews, ctx.head_sha, ctx.author_login)
    for approval in candidates:
        membership = await gh_api.find_active_team_membership(
            gh, org=ctx.org, username=approval.reviewer_login, team_slugs=parsed.team_slugs
        )
        if membership is not None:
            return Outcome(
                kind=OutcomeKind.AUTHORIZED_APPROVAL,
                message=(
                    f"PR approved by codeowner {approval.reviewer_login!r} "
                    f"(team=@{ctx.org}/{membership.team_slug}) at {ctx.head_sha}."
                ),
                head_sha=ctx.head_sha,
            )

    approver_summary = ", ".join(a.reviewer_login for a in candidates) if candidates else "(none)"
    teams_summary = ", ".join(f"@{ctx.org}/{t}" for t in parsed.team_slugs)
    return Outcome(
        kind=OutcomeKind.DENIED_NO_APPROVAL,
        message=(
            f"PR author {ctx.author_login!r} is not a codeowner. "
            f"Approvals at HEAD {ctx.head_sha} came from: {approver_summary}. "
            f"None of them are active members of a codeowner team [{teams_summary}]. "
            "A codeowner must submit an APPROVE review on the current commit."
        ),
        head_sha=ctx.head_sha,
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
