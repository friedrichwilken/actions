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
from datetime import UTC, datetime


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
    submitted_at: datetime | None
    # ``None`` when the API omits the field (rare — legacy reviews, or a
    # PENDING review that hasn't been submitted yet). Sorts before all
    # real timestamps in the defensive-sort step below, i.e. the
    # unknown-time review is treated as the OLDEST possible submission.
    # That's the fail-open direction: a review with unknown submission
    # time will lose to any review with a real timestamp.


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
    # Sort by ``submitted_at`` ascending BEFORE deduplicating. GitHub's
    # docs say reviews are returned in chronological order, but that
    # promise doesn't survive pagination reordering, same-second ties, or
    # a future API change. Explicit sort here means the dict-overwrite
    # dedup below is deterministic: the highest ``submitted_at`` per
    # reviewer wins regardless of the input order.
    #
    # Reviews with ``submitted_at is None`` sort first (treated as
    # oldest) — the fail-open direction for the "did this reviewer take
    # a later stance" question. A dismissed or force-pushed review with
    # a real timestamp will always beat an unknown-time one.
    ordered = sorted(reviews, key=_sort_key)

    # Deduplicate to the latest non-COMMENTED state per reviewer.
    latest_by_reviewer: dict[str, Review] = {}
    for review in ordered:
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


# Anchor for reviews with ``submitted_at is None``. ``datetime.min`` sorts
# before every real timestamp. This anchor is deliberately NAIVE (no
# tzinfo) to match the naive-normalized real timestamps produced by
# ``_sort_key`` — mixing a tz-aware anchor with naive keys would raise
# "can't compare offset-naive and offset-aware datetimes". Do NOT add a
# tzinfo here.
_MIN_TIMESTAMP = datetime.min.replace(tzinfo=None)


def _sort_key(r: Review) -> datetime:
    if r.submitted_at is None:
        return _MIN_TIMESTAMP
    ts = r.submitted_at
    if ts.tzinfo is not None:
        # Convert to the true UTC instant, then drop tzinfo, so the sort
        # key is naive-but-correct. Stripping tzinfo without converting
        # would order by wall-clock time and misorder a non-UTC timestamp
        # (GitHub always returns UTC 'Z', but a hand-crafted event or a
        # future githubkit change could carry an offset).
        ts = ts.astimezone(UTC).replace(tzinfo=None)
    return ts
