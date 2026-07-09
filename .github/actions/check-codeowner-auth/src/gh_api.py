"""
GitHub API access for the auth-gate action.

Wraps the specific REST endpoints the gate needs into typed helpers with
clear error semantics. Uses ``githubkit`` under the hood — see
<https://github.com/yanyongyu/githubkit>.

All functions here are async because ``githubkit`` is async-first; the
orchestrator awaits them from a single ``asyncio.run(main())``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime

from githubkit import GitHub
from githubkit.exception import RequestFailed

from .approvals import Review


@dataclass(frozen=True)
class CodeownersFile:
    """A CODEOWNERS file located in a repository."""

    path: str  # ".github/CODEOWNERS", "CODEOWNERS", or "docs/CODEOWNERS"
    content: str  # UTF-8 decoded


# CODEOWNERS resolution order per GitHub docs. The first file that exists wins.
CODEOWNERS_LOCATIONS: tuple[str, ...] = (
    ".github/CODEOWNERS",
    "CODEOWNERS",
    "docs/CODEOWNERS",
)


async def fetch_codeowners(
    gh: GitHub,
    *,
    owner: str,
    repo: str,
    ref: str,
) -> CodeownersFile | None:
    """Fetch the CODEOWNERS file for a repository at a given ref.

    Reads via the contents API rather than the runner filesystem, so a
    ``pull_request_target`` event doesn't accidentally read the attacker's
    PR-head version.

    Args:
        gh: Authenticated GitHub client.
        owner: Repository owner (org).
        repo: Repository name.
        ref: Branch or commit SHA to read from. Should be the PR's base ref.

    Returns:
        The first CODEOWNERS file found in the standard locations, or
        ``None`` if the repo has no CODEOWNERS file.
    """
    for path in CODEOWNERS_LOCATIONS:
        try:
            resp = await gh.rest.repos.async_get_content(owner=owner, repo=repo, path=path, ref=ref)
        except RequestFailed as e:
            if e.response.status_code == 404:
                continue
            raise
        data = resp.parsed_data
        # The contents API returns a list for directories; a single object
        # for files. If the caller pointed at a directory, ignore it.
        if isinstance(data, list):
            continue
        encoding = getattr(data, "encoding", None)
        content = getattr(data, "content", None)
        if encoding == "base64" and content:
            text = base64.b64decode(content).decode("utf-8")
            return CodeownersFile(path=path, content=text)
    return None


@dataclass(frozen=True)
class TeamMembership:
    """A user's active membership in a specific team."""

    team_slug: str
    role: str  # "member" | "maintainer"


async def find_active_team_membership(
    gh: GitHub,
    *,
    org: str,
    username: str,
    team_slugs: tuple[str, ...],
) -> TeamMembership | None:
    """Return the first team ``username`` is an active member of, or None.

    "Active" membership excludes pending invites: the GitHub API returns
    ``200 {state: 'pending'}`` for a user who has been invited but not yet
    accepted, and we do NOT count those as members.

    ``getMembershipForUserInOrg`` recurses into child teams — a member of
    a nested team appears as a member of the parent. This is documented
    behavior of the gate and mirrors how CODEOWNERS review requests work
    in GitHub's own UI.

    Args:
        gh: Authenticated GitHub client.
        org: Organization slug.
        username: User to check.
        team_slugs: Teams to check membership against, in preference order.

    Returns:
        A ``TeamMembership`` for the first team ``username`` is active in,
        or ``None`` if the user is not an active member of any team.
    """
    for team_slug in team_slugs:
        try:
            resp = await gh.rest.teams.async_get_membership_for_user_in_org(
                org=org, team_slug=team_slug, username=username
            )
        except RequestFailed as e:
            if e.response.status_code == 404:
                continue
            raise
        data = resp.parsed_data
        if getattr(data, "state", None) == "active":
            return TeamMembership(team_slug=team_slug, role=getattr(data, "role", "member"))
    return None


async def list_pr_reviews(
    gh: GitHub,
    *,
    owner: str,
    repo: str,
    pull_number: int,
) -> list[Review]:
    """Fetch all reviews on a PR, paginated.

    Maps the API response into our own ``Review`` dataclass so downstream
    filtering doesn't depend on ``githubkit`` types.

    Args:
        gh: Authenticated GitHub client.
        owner: Repository owner.
        repo: Repository name.
        pull_number: PR number.

    Returns:
        All reviews, in the API's return order (roughly chronological).
    """
    reviews: list[Review] = []
    async for review in gh.rest.paginate(
        gh.rest.pulls.async_list_reviews,
        owner=owner,
        repo=repo,
        pull_number=pull_number,
        per_page=100,
    ):
        user = getattr(review, "user", None)
        if user is None:
            # Ghost user (account deleted). Their reviews cannot count as
            # authorization anyway — a login of ``None`` won't match any
            # team membership check.
            continue
        submitted_at = getattr(review, "submitted_at", None)
        # githubkit types ``submitted_at`` as ``Literal[UNSET] | datetime | None``.
        # Normalize UNSET and any non-datetime falsy value to None so the
        # sort key can rely on ``datetime | None``.
        if not isinstance(submitted_at, datetime):
            submitted_at = None
        reviews.append(
            Review(
                reviewer_login=getattr(user, "login", ""),
                reviewer_type=getattr(user, "type", ""),
                state=getattr(review, "state", ""),
                commit_id=getattr(review, "commit_id", "") or "",
                submitted_at=submitted_at,
            )
        )
    return reviews
