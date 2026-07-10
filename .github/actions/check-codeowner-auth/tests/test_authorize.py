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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_review",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_AUTHOR

    async def test_missing_pr_denied(self) -> None:
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_MISSING_CODEOWNERS

    async def test_first_path_wins(self, respx_mock: respx.MockRouter) -> None:
        # Serve .github/CODEOWNERS; the fallback locations (CODEOWNERS,
        # docs/CODEOWNERS) must NOT be queried. Register routes for the
        # fallbacks so we can assert they were never called — this pins the
        # short-circuit in fetch_codeowners (a regression that queried all
        # three paths would trip the assertions below).
        _, payload = make_event()
        first = respx_mock.get(
            "https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS"
        ).mock(return_value=_codeowners_response("* @acme/team-a\n"))
        fallback_root = respx_mock.get(
            "https://api.github.com/repos/acme/widget/contents/CODEOWNERS"
        ).mock(return_value=_codeowners_response("* @acme/should-not-be-read\n"))
        fallback_docs = respx_mock.get(
            "https://api.github.com/repos/acme/widget/contents/docs/CODEOWNERS"
        ).mock(return_value=_codeowners_response("* @acme/should-not-be-read\n"))
        respx_mock.get(
            "https://api.github.com/orgs/acme/teams/team-a/memberships/external-contributor"
        ).mock(return_value=_membership_not_found())
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([])
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL
        # The first location was used; the fallbacks were never queried.
        assert first.called
        assert not fallback_root.called
        assert not fallback_docs.called

    async def test_no_team_entries_denied(self, respx_mock: respx.MockRouter) -> None:
        _, payload = make_event()
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @some-user\n")
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_TEAM_CODEOWNERS
        # Diagnostic should mention the individual we ignored.
        assert "@some-user" in outcome.message

    async def test_empty_login_review_is_dropped(self, respx_mock: respx.MockRouter) -> None:
        # A review whose user object has an empty login (deleted/ghost-ish
        # payload) must be dropped by list_pr_reviews, not carried as an
        # empty-login row. Here it's the only "approval" at HEAD; dropping it
        # leaves no codeowner approval → denied (fail-closed). If the empty
        # login leaked through it could never match a team anyway, but this
        # pins that the row is discarded at the source.
        _, payload = make_event(author_login="external")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/external").mock(
            return_value=_membership_not_found()
        )
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("")])
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL


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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
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
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.head_sha == "sha-xyz"
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_head_sha_absent_on_missing_pr(self) -> None:
        # No PR → no head_sha available. One of only three denial modes
        # where head_sha is legitimately absent (also:
        # DENIED_UNSUPPORTED_EVENT and DENIED_MALFORMED_PAYLOAD).
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload={},
                trusted_bot_ids_raw="",
            )
        assert outcome.head_sha is None


@pytest.mark.asyncio
class TestMalformedPayload:
    """Payload with missing / wrong-typed fields must return a clean
    ``DENIED_MALFORMED_PAYLOAD`` outcome, not an uncaught KeyError or
    TypeError. Downstream contract: no head_sha (the extract step failed
    before one could be read)."""

    @pytest.mark.parametrize(
        "mutation",
        [
            # user with no login
            lambda p: p["pull_request"].__setitem__("user", {}),
            # head with no sha
            lambda p: p["pull_request"].__setitem__("head", {}),
            # base with no ref/repo
            lambda p: p["pull_request"].__setitem__("base", {}),
            # missing number
            lambda p: p["pull_request"].pop("number"),
            # unparseable number
            lambda p: p["pull_request"].__setitem__("number", "not-an-int"),
            # unparseable user.id
            lambda p: p["pull_request"]["user"].__setitem__("id", "not-an-int"),
        ],
    )
    async def test_malformed_pr_returns_clean_outcome(self, mutation) -> None:
        _, payload = make_event()
        mutation(payload)
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_MALFORMED_PAYLOAD
        assert outcome.head_sha is None

    async def test_pull_request_wrong_type_returns_clean_outcome(self) -> None:
        # pull_request is present but is not a dict (e.g. a list from a
        # replayed/hand-crafted payload). ``_extract_pr_context`` catches
        # the TypeError.
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload={"pull_request": ["not", "a", "dict"]},
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_MALFORMED_PAYLOAD


@pytest.mark.asyncio
class TestApiErrorHandling:
    """Non-404 API failures must produce ``DENIED_API_ERROR`` with
    ``head_sha`` populated, not an uncaught traceback."""

    async def test_5xx_on_codeowners_fetch_returns_api_error_with_head_sha(
        self, respx_mock: respx.MockRouter
    ) -> None:
        _, payload = make_event(head_sha="sha-abc")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=Response(503, json={"message": "Service Unavailable"})
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_API_ERROR
        assert outcome.head_sha == "sha-abc"
        assert "503" in outcome.message

    async def test_secondary_rate_limit_on_team_membership_returns_api_error(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # Secondary rate limits come back as 403 with a message body — not
        # a 404, so the gh_api helper re-raises. Must surface as
        # DENIED_API_ERROR, not an uncaught RequestFailed.
        _, payload = make_event(head_sha="sha-abc", author_login="alice")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a\n")
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/alice").mock(
            return_value=Response(
                403,
                headers={"x-ratelimit-remaining": "0"},
                json={"message": "API rate limit exceeded"},
            )
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_API_ERROR
        assert outcome.head_sha == "sha-abc"

    async def test_transport_error_returns_api_error(self, respx_mock: respx.MockRouter) -> None:
        # Transport-level failure (connection refused, DNS, TLS handshake).
        # httpx raises subclasses of httpx.HTTPError before githubkit ever
        # sees a Response.
        import httpx as _httpx

        _, payload = make_event(head_sha="sha-abc")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            side_effect=_httpx.ConnectError("connection refused")
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
            )
        assert outcome.kind == OutcomeKind.DENIED_API_ERROR
        assert outcome.head_sha == "sha-abc"


@pytest.mark.asyncio
class TestIndividualOwners:
    """The TEMPORARY allow_individual_owners bridge flag.

    Off by default (permanent teams-only posture); when on, individual
    ``@handle`` CODEOWNERS entries also authorize. These tests pin both the
    default-off regression guard and the flag-on behavior, including that the
    individual approval path still passes every existing approval filter.
    """

    async def test_flag_off_handle_only_codeowners_denied(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # Regression guard: with the flag OFF (default), a CODEOWNERS with only
        # individual handles must still be rejected — the permanent behavior.
        _, payload = make_event(author_login="alice")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @alice\n")
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                # allow_individual_owners defaults to False
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_TEAM_CODEOWNERS

    async def test_flag_on_author_is_individual_authorized(
        self, respx_mock: respx.MockRouter
    ) -> None:
        _, payload = make_event(author_login="alice")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @alice\n")
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_AUTHOR
        assert "individual" in outcome.message.lower()

    async def test_flag_on_author_case_insensitive(self, respx_mock: respx.MockRouter) -> None:
        # CODEOWNERS lists @Alice; PR author login is alice.
        _, payload = make_event(author_login="alice")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @Alice\n")
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_AUTHOR

    async def test_flag_on_individual_approval_authorized(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # Author is not a codeowner; an individual codeowner (bob) approves at HEAD.
        _, payload = make_event(author_login="external", head_sha="sha-current")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @bob\n")
        )
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("bob")])
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_APPROVAL
        assert "individual" in outcome.message.lower()

    async def test_flag_on_individual_bot_approval_denied(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # A bot listed as an individual codeowner still can't approve — the
        # approval filter rejects bots BEFORE the individual match is consulted.
        _, payload = make_event(author_login="external")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @some-bot\n")
        )
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("some-bot", user_type="Bot")])
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_flag_on_individual_self_approval_denied(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # Author is NOT a listed codeowner, but IS listed... no. To isolate
        # "a self-approval doesn't count," the author must not be a listed
        # individual (else the AUTHOR path authorizes before approvals are
        # even fetched). So: author @external is not listed; @external is the
        # only reviewer and self-approves. valid_approvals_at_head drops the
        # self-review, leaving no candidate → denied.
        _, payload = make_event(author_login="external", head_sha="sha-current")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @bob\n")
        )
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("external")])
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        # The self-review is filtered; @external is not a listed owner anyway.
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_flag_on_individual_stale_approval_denied(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # Individual codeowner approved, but on an OLD commit. Stale-SHA
        # filter drops it before the individual match.
        _, payload = make_event(author_login="external", head_sha="sha-current")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @bob\n")
        )
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([_review("bob", commit_id="sha-old")])
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_flag_on_mixed_team_and_individual(self, respx_mock: respx.MockRouter) -> None:
        # CODEOWNERS has both a team and an individual. Author is the
        # individual (not on the team). Team lookup 404s; individual path
        # authorizes.
        _, payload = make_event(author_login="alice")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a @alice\n")
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/alice").mock(
            return_value=_membership_not_found()
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_AUTHOR
        assert "individual" in outcome.message.lower()

    async def test_flag_on_mixed_team_path_still_works(self, respx_mock: respx.MockRouter) -> None:
        # Same mixed CODEOWNERS, but the author is a team member (not the
        # individual). Team path authorizes; message is the team message.
        _, payload = make_event(author_login="carol")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @acme/team-a @alice\n")
        )
        respx_mock.get("https://api.github.com/orgs/acme/teams/team-a/memberships/carol").mock(
            return_value=_membership_active("team-a")
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        assert outcome.kind == OutcomeKind.AUTHORIZED_AUTHOR
        assert "team-a" in outcome.message

    async def test_flag_on_author_not_listed_no_approval_denied(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # Flag on, author not a listed individual, no approvals → denied.
        _, payload = make_event(author_login="stranger")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("* @alice\n")
        )
        respx_mock.get("https://api.github.com/repos/acme/widget/pulls/42/reviews").mock(
            return_value=_reviews_response([])
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_APPROVAL

    async def test_flag_on_empty_codeowners_still_denied(
        self, respx_mock: respx.MockRouter
    ) -> None:
        # Fail-closed preserved: flag on but CODEOWNERS has no usable owners.
        _, payload = make_event(author_login="alice")
        respx_mock.get("https://api.github.com/repos/acme/widget/contents/.github/CODEOWNERS").mock(
            return_value=_codeowners_response("# just a comment\n")
        )
        async with GitHub("fake-token", auto_retry=False) as gh:
            outcome = await authorize(
                gh,
                event_name="pull_request_target",
                event_payload=payload,
                trusted_bot_ids_raw="",
                allow_individual_owners=True,
            )
        assert outcome.kind == OutcomeKind.DENIED_NO_TEAM_CODEOWNERS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
