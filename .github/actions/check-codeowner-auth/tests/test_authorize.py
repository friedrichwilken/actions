"""Tests for the authorize orchestrator.

These are integration tests over the state machine: given an event
payload and mocked GitHub API responses, verify the correct ``Outcome``
comes out. The pure modules (``codeowners``, ``approvals``,
``trusted_bots``) have their own unit tests; here we prove the wiring.

Uses ``respx`` to intercept ``httpx`` calls made by ``githubkit``. No
real network traffic.
"""

from __future__ import annotations

import base64

import pytest
import respx
from githubkit import GitHub
from httpx import Response

from src.authorize import OutcomeKind, authorize

# ── Fixture builders ──────────────────────────────────────────────────


def make_event(
    *,
    event_name: str = "pull_request_target",
    author_login: str = "external-contributor",
    author_id: int = 999,
    author_type: str = "User",
    head_sha: str = "sha-current",
    base_ref: str = "main",
    org: str = "acme",
    repo: str = "widget",
    pr_number: int = 42,
) -> tuple[str, dict]:
    """Build a synthetic event payload for the orchestrator to consume."""
    payload = {
        "pull_request": {
            "number": pr_number,
            "user": {
                "login": author_login,
                "id": author_id,
                "type": author_type,
            },
            "head": {"sha": head_sha},
            "base": {
                "ref": base_ref,
                "repo": {
                    "name": repo,
                    "owner": {"login": org},
                },
            },
        }
    }
    return event_name, payload


def _codeowners_response(content: str) -> Response:
    encoded = base64.b64encode(content.encode()).decode()
    return Response(
        200,
        json={
            "name": "CODEOWNERS",
            "path": ".github/CODEOWNERS",
            "type": "file",
            "encoding": "base64",
            "content": encoded,
            "size": len(content),
            "sha": "codeowners-sha",
            "url": "",
            "git_url": "",
            "html_url": "",
            "download_url": "",
            "_links": {"self": "", "git": "", "html": ""},
        },
    )


def _membership_active(team_slug: str) -> Response:
    return Response(
        200,
        json={
            "url": f"https://api.github.com/teams/{team_slug}/memberships/user",
            "role": "member",
            "state": "active",
        },
    )


def _membership_pending() -> Response:
    return Response(
        200,
        json={
            "url": "https://api.github.com/teams/x/memberships/user",
            "role": "member",
            "state": "pending",
        },
    )


def _membership_not_found() -> Response:
    return Response(404, json={"message": "Not Found"})


def _codeowners_not_found() -> Response:
    return Response(404, json={"message": "Not Found"})


def _reviews_response(reviews: list[dict]) -> Response:
    return Response(200, json=reviews)


def _user(login: str, *, user_id: int = 100, user_type: str = "User") -> dict:
    """Full GitHub User payload — githubkit validates all required fields."""
    return {
        "login": login,
        "id": user_id,
        "node_id": f"U_{user_id}",
        "avatar_url": f"https://avatars.githubusercontent.com/u/{user_id}",
        "gravatar_id": "",
        "url": f"https://api.github.com/users/{login}",
        "html_url": f"https://github.com/{login}",
        "followers_url": "",
        "following_url": "",
        "gists_url": "",
        "starred_url": "",
        "subscriptions_url": "",
        "organizations_url": "",
        "repos_url": "",
        "events_url": "",
        "received_events_url": "",
        "type": user_type,
        "site_admin": False,
    }


def _review(
    login: str,
    *,
    state: str = "APPROVED",
    commit_id: str = "sha-current",
    user_type: str = "User",
) -> dict:
    return {
        "id": 1,
        "node_id": "PR_1",
        "user": _user(login, user_type=user_type),
        "body": "",
        "state": state,
        "html_url": "",
        "pull_request_url": "",
        "_links": {"html": {"href": ""}, "pull_request": {"href": ""}},
        "submitted_at": "2026-01-01T00:00:00Z",
        "commit_id": commit_id,
        "author_association": "MEMBER",
    }


# ── Tests ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestEventGate:
    async def test_unsupported_event_denied(self) -> None:
        _, payload = make_event(event_name="issue_comment")
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="issue_comment",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_UNSUPPORTED_EVENT

    async def test_pull_request_review_event_accepted(self, respx_mock: respx.MockRouter) -> None:
        # ``pull_request_review`` is one of only two supported events; the
        # end-to-end flow must be identical to ``pull_request_target`` because
        # the same authorization logic applies (the review event's role is to
        # re-trigger the gate now that an approval landed). This test proves
        # the wiring — a future change that adds review-event-specific logic
        # will need to update or extend it explicitly.
        _, payload = make_event(event_name="pull_request_review", author_login="alice")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/alice").mock(
            return_value=_membership_active("team-a")
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_review",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_AUTHOR

    async def test_missing_pr_denied(self) -> None:
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload={},
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_MISSING_PR


@pytest.mark.asyncio
class TestTrustedBot:
    async def test_trusted_bot_authorized_without_api_calls(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # No routes registered → any accidental API call would raise. Prove
        # the trusted-bot path short-circuits before hitting the network.
        _, payload = make_event(author_login="renovate[bot]", author_id=29139614, author_type="Bot")
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="29139614",
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_TRUSTED_BOT
        assert outcome.head_sha == "sha-current"

    async def test_matching_id_but_not_bot_type_falls_through(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # An attacker who somehow re-registers a login with matching id
        # would still be user.type=='User' and must not short-circuit.
        _, payload = make_event(author_login="attacker", author_id=29139614, author_type="User")
        # No CODEOWNERS → will end in DENIED_MISSING_CODEOWNERS, proving we
        # fell through the trusted-bot gate.
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_not_found()
        )
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/CODEOWNERS").mock(
            return_value=_codeowners_not_found()
        )
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/docs/CODEOWNERS").mock(
            return_value=_codeowners_not_found()
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="29139614",
            )
        assert outcome.kind == OutcomeKind.DENIED_MISSING_CODEOWNERS


@pytest.mark.asyncio
class TestCodeownersFetch:
    async def test_missing_codeowners_all_three_paths_denied(
        self, respx_mock: respx.MockRouter
    ) -> None:
        _, payload = make_event()
        for path in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]:
            respx_mock.get(f"https://api.github.com/repos/acme/widget/contents/{path}").mock(
                return_value=_codeowners_not_found()
            )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_MISSING_CODEOWNERS

    async def test_first_path_wins(self, respx_mock: respx.MockRouter) -> None:
        # Serve .github/CODEOWNERS; the fallback locations must not be
        # queried. (respx will accept unmatched calls in some configs;
        # we just verify the first response was used by checking that
        # the author fails membership and we end up in NO_APPROVAL.)
        _, payload = make_event()
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-a/memberships/external-contributor"
        ).mock(return_value=_membership_not_found())
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([])
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_no_team_entries_denied(self, respx_mock: respx.MockRouter) -> None:
        _, payload = make_event()
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @some-user\n")
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_TEAM_CODEOWNERS
        # Diagnostic should mention the individual we ignored.
        assert "@some-user" in outcome.message


@pytest.mark.asyncio
class TestAuthorMembership:
    async def test_author_is_codeowner_authorized(self, respx_mock: respx.MockRouter) -> None:
        _, payload = make_event(author_login="alice")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/alice").mock(
            return_value=_membership_active("team-a")
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_AUTHOR

    async def test_author_pending_invite_not_authorized(self, respx_mock: respx.MockRouter) -> None:
        # The classic regression the port fixes: pending invite must NOT
        # authorize. Old code accepted any non-404 as membership.
        _, payload = make_event(author_login="alice")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/alice").mock(
            return_value=_membership_pending()
        )
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([])
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL


@pytest.mark.asyncio
class TestApprovalAuthorization:
    async def test_codeowner_approved_at_head_authorized(
        self, respx_mock: respx.MockRouter
    ) -> None:
        _, payload = make_event()
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-a/memberships/external-contributor"
        ).mock(return_value=_membership_not_found())
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("alice")])
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/alice").mock(
            return_value=_membership_active("team-a")
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_APPROVAL

    async def test_approval_on_stale_sha_denied(self, respx_mock: respx.MockRouter) -> None:
        _, payload = make_event()  # head_sha = "sha-current"
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-a/memberships/external-contributor"
        ).mock(return_value=_membership_not_found())
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("alice", commit_id="sha-old")])
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_bot_approval_at_head_denied(self, respx_mock: respx.MockRouter) -> None:
        _, payload = make_event()
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-a/memberships/external-contributor"
        ).mock(return_value=_membership_not_found())
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("some-bot", user_type="Bot")])
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_approver_pending_membership_denied(self, respx_mock: respx.MockRouter) -> None:
        # Approver is a real user with a real approval at HEAD, but has
        # only a pending team invite → not a codeowner.
        _, payload = make_event()
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-a/memberships/external-contributor"
        ).mock(return_value=_membership_not_found())
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("alice")])
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/alice").mock(
            return_value=_membership_pending()
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_multiple_teams_first_matching_approver_authorized(
        self, respx_mock: respx.MockRouter
    ) -> None:
        _, payload = make_event()
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a @acme/team-b\n")
        )
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-a/memberships/external-contributor"
        ).mock(return_value=_membership_not_found())
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-b/memberships/external-contributor"
        ).mock(return_value=_membership_not_found())
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("alice")])
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/alice").mock(
            return_value=_membership_not_found()
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-b/memberships/alice").mock(
            return_value=_membership_active("team-b")
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_APPROVAL
        assert "team-b" in outcome.message


@pytest.mark.asyncio
class TestHeadShaAlwaysEmitted:
    """The ``head-sha`` output must be set even on denials, because
    downstream jobs pin to it via ``needs.authorize.outputs.head-sha``."""

    async def test_head_sha_on_authorized(self, respx_mock: respx.MockRouter) -> None:
        _, payload = make_event(head_sha="sha-xyz")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-a/memberships/external-contributor"
        ).mock(return_value=_membership_active("team-a"))
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.head_sha == "sha-xyz"

    async def test_head_sha_on_denied_no_approval(self, respx_mock: respx.MockRouter) -> None:
        _, payload = make_event(head_sha="sha-xyz")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-a/memberships/external-contributor"
        ).mock(return_value=_membership_not_found())
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([])
        )
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.head_sha == "sha-xyz"
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_head_sha_absent_on_missing_pr(self) -> None:
        # No PR → no head_sha available. This is the one denial where
        # ``head_sha`` is legitimately absent.
        async with GitHub("fake-token") as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload={},
                trusted_bot_ids_raw="",
            )
        assert outcome.head_sha is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
