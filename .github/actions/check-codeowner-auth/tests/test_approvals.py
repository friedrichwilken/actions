"""Tests for the review-filtering logic."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.approvals import Review, valid_approvals_at_head


def _review(
    *,
    login: str = "alice",
    reviewer_type: str = "User",
    state: str = "APPROVED",
    commit_id: str = "abc123",
    submitted_at: datetime | None = None,
) -> Review:
    # Default timestamp is a fixed anchor rather than None so the
    # existing tests don't accidentally observe "unknown-time review
    # sorts first" behavior. When a test wants to distinguish order it
    # passes an explicit timestamp.
    if submitted_at is None:
        submitted_at = datetime(2026, 1, 1, tzinfo=UTC)
    return Review(
        reviewer_login=login,
        reviewer_type=reviewer_type,
        state=state,
        commit_id=commit_id,
        submitted_at=submitted_at,
    )


class TestBasicFiltering:
    def test_single_valid_approval(self) -> None:
        r = _review()
        assert valid_approvals_at_head([r], "abc123", "author") == (r,)

    def test_stale_sha_rejected(self) -> None:
        r = _review(commit_id="old-sha")
        assert valid_approvals_at_head([r], "new-sha", "author") == ()

    def test_bot_approval_rejected(self) -> None:
        r = _review(reviewer_type="Bot")
        assert valid_approvals_at_head([r], "abc123", "author") == ()

    def test_self_approval_rejected(self) -> None:
        # Defense-in-depth: GitHub server-side already rejects with 422,
        # but if that check is ever bypassed we don't want to authorize.
        r = _review(login="author")
        assert valid_approvals_at_head([r], "abc123", "author") == ()

    def test_changes_requested_rejected(self) -> None:
        r = _review(state="CHANGES_REQUESTED")
        assert valid_approvals_at_head([r], "abc123", "author") == ()

    def test_dismissed_rejected(self) -> None:
        r = _review(state="DISMISSED")
        assert valid_approvals_at_head([r], "abc123", "author") == ()


class TestLatestStateWins:
    """When a reviewer submits multiple reviews, only the latest counts."""

    def test_approved_then_changes_requested(self) -> None:
        # Reviewer approved, then requested changes — latest wins, no approval.
        reviews = [
            _review(state="APPROVED"),
            _review(state="CHANGES_REQUESTED"),
        ]
        assert valid_approvals_at_head(reviews, "abc123", "author") == ()

    def test_changes_requested_then_approved(self) -> None:
        # Reviewer asked for changes, then approved after fixes.
        reviews = [
            _review(state="CHANGES_REQUESTED"),
            _review(state="APPROVED"),
        ]
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert len(result) == 1
        assert result[0].state == "APPROVED"

    def test_comments_do_not_reset_state(self) -> None:
        # A COMMENTED review after an APPROVED one must not erase the approval.
        reviews = [
            _review(state="APPROVED"),
            _review(state="COMMENTED"),
        ]
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert len(result) == 1
        assert result[0].state == "APPROVED"

    def test_multiple_reviewers_independent(self) -> None:
        reviews = [
            _review(login="alice", state="APPROVED"),
            _review(login="bob", state="CHANGES_REQUESTED"),
            _review(login="carol", state="APPROVED"),
        ]
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert {r.reviewer_login for r in result} == {"alice", "carol"}


class TestCombinations:
    """The filter rules combined."""

    def test_bot_approval_stale_and_wrong_author_all_rejected(self) -> None:
        reviews = [
            _review(login="alice", reviewer_type="Bot"),  # bot
            _review(login="bob", commit_id="old-sha"),  # stale
            _review(login="author"),  # self
        ]
        assert valid_approvals_at_head(reviews, "abc123", "author") == ()

    def test_one_valid_mixed_with_invalid(self) -> None:
        reviews = [
            _review(login="alice", reviewer_type="Bot"),  # bot: rejected
            _review(login="bob", commit_id="old-sha"),  # stale: rejected
            _review(login="carol"),  # valid
            _review(login="author"),  # self: rejected
        ]
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert {r.reviewer_login for r in result} == {"carol"}


class TestEdgeCases:
    def test_empty_reviews(self) -> None:
        assert valid_approvals_at_head([], "abc123", "author") == ()

    def test_only_comments(self) -> None:
        reviews = [_review(state="COMMENTED")]
        assert valid_approvals_at_head(reviews, "abc123", "author") == ()


class TestChronologicalSort:
    """The defensive ``submitted_at`` sort makes dedup deterministic
    regardless of the order the API returns reviews in."""

    def test_dedup_uses_submitted_at_not_input_order(self) -> None:
        # Reviewer approves (t=1) then requests changes (t=2). The API
        # returns them in REVERSED order (changes-requested first). Without
        # the sort, dict-overwrite would end with the APPROVED review as
        # "latest" and the gate would wrongly authorize a review that was
        # later withdrawn. With the sort, CHANGES_REQUESTED (t=2) wins.
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        t2 = datetime(2026, 1, 1, 12, 0, 5, tzinfo=UTC)
        reviews = [
            _review(login="alice", state="CHANGES_REQUESTED", submitted_at=t2),
            _review(login="alice", state="APPROVED", submitted_at=t1),
        ]
        # Input order has APPROVED last → a naive dict-overwrite that
        # trusted input order would keep APPROVED. The sort must flip this.
        assert valid_approvals_at_head(reviews, "abc123", "author") == ()

    def test_later_approval_wins_when_input_reversed(self) -> None:
        # Reverse case: changes-requested (t=1) then approved (t=2), but the
        # API returns approved first. Sort must keep the later APPROVED.
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        t2 = datetime(2026, 1, 1, 12, 0, 5, tzinfo=UTC)
        reviews = [
            _review(login="alice", state="APPROVED", submitted_at=t2),
            _review(login="alice", state="CHANGES_REQUESTED", submitted_at=t1),
        ]
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert len(result) == 1
        assert result[0].state == "APPROVED"

    def test_none_submitted_at_sorts_as_oldest(self) -> None:
        # A review with no submitted_at (legacy / PENDING) must lose to a
        # real-timestamped review from the same reviewer. Here the
        # unknown-time review is APPROVED and the real one is
        # CHANGES_REQUESTED — the real (later) one must win → denied.
        real = datetime(2026, 1, 1, tzinfo=UTC)
        reviews = [
            _review(login="alice", state="APPROVED", submitted_at=None),
            _review(login="alice", state="CHANGES_REQUESTED", submitted_at=real),
        ]
        assert valid_approvals_at_head(reviews, "abc123", "author") == ()

    def test_naive_and_aware_timestamps_do_not_crash_sort(self) -> None:
        # Defensive: if one review carries a tz-naive datetime (shouldn't
        # happen from the real API, but a hand-crafted event or future
        # githubkit change could), the sort key normalizes both sides to
        # naive so Python doesn't raise "can't compare offset-naive and
        # offset-aware datetimes".
        aware = datetime(2026, 1, 1, 12, 0, 5, tzinfo=UTC)
        naive = datetime(2026, 1, 1, 12, 0, 0)
        reviews = [
            _review(login="alice", state="APPROVED", submitted_at=aware),
            _review(login="bob", state="APPROVED", submitted_at=naive),
        ]
        # Should not raise; both are valid approvals at head.
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert {r.reviewer_login for r in result} == {"alice", "bob"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
