"""
Review filtering for the approval check.

Reduces a raw list of PR reviews to the set that count as codeowner
approvals at the current HEAD commit.

Rules applied:
- Keep only the LATEST non-COMMENTED review per reviewer. A later
  ``CHANGES_REQUESTED`` beats an earlier ``APPROVED``.
- Reviewer must be a ``User``, not a ``Bot``. Bots that get added to a
  codeowner team are a common exploit path (auto-approve-docs bots
  tricked by crafted PRs) — filter them out here regardless of team
  membership.
- Reviewer cannot be the PR author. GitHub server-side blocks
  self-approval with HTTP 422; this is defense-in-depth in case that
  check is ever bypassed by a race or edge case.
- Review's ``commit_id`` must equal the PR's current HEAD SHA. Approvals
  on prior commits are stale — a force-push invalidates them.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Review:
    """The subset of a GitHub review payload the filter needs.

    Modeled explicitly rather than passed through as ``dict`` so tests
    don't have to construct octokit-shaped fixtures and callers can't
    accidentally rely on fields we haven't thought about.
    """

    reviewer_login: str
    reviewer_type: str  # "User" | "Bot" | ...
    state: str  # "APPROVED" | "CHANGES_REQUESTED" | "COMMENTED" | "DISMISSED" | "PENDING"
    commit_id: str


def valid_approvals_at_head(
    reviews: Iterable[Review],
    head_sha: str,
    pr_author_login: str,
) -> tuple[Review, ...]:
    """Return the reviews that count as valid codeowner-eligible approvals.

    The returned reviews are candidates — the caller still needs to verify
    each reviewer's team membership.

    Args:
        reviews: All reviews on the PR, in any order.
        head_sha: The current PR HEAD commit SHA (from the event payload).
        pr_author_login: The PR author's login, for self-approval filtering.

    Returns:
        Tuple of reviews that pass the filter, deduplicated by reviewer
        (latest non-COMMENTED wins). Order is not meaningful.
    """
    # Deduplicate to the latest non-COMMENTED state per reviewer. Reviews
    # are returned by the API in chronological order, so later entries
    # overwrite earlier ones.
    latest_by_reviewer: dict[str, Review] = {}
    for review in reviews:
        if review.state == "COMMENTED":
            # Comments don't change the review state — the "latest" review
            # is the latest one that actually took a stance.
            continue
        latest_by_reviewer[review.reviewer_login] = review

    return tuple(
        r
        for r in latest_by_reviewer.values()
        if r.state == "APPROVED"
        and r.commit_id == head_sha
        and r.reviewer_type == "User"
        and r.reviewer_login != pr_author_login
    )
