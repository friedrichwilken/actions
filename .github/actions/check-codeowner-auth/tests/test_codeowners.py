"""Tests for the CODEOWNERS parser.

The parser is the security-relevant piece: it decides which teams have
authority to gate PRs. Every edge case matters.
"""

from __future__ import annotations

import pytest

from src.codeowners import parse


class TestBasicTeamEntries:
    """Simple @org/team entries in different positions."""

    def test_single_team_on_wildcard(self) -> None:
        r = parse("* @acme/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_multiple_teams_on_one_line(self) -> None:
        r = parse("* @acme/team-a @acme/team-b\n", "acme")
        assert r.team_slugs == ("team-a", "team-b")

    def test_teams_across_multiple_lines(self) -> None:
        r = parse("* @acme/team-a\ndocs/ @acme/team-b\n", "acme")
        assert r.team_slugs == ("team-a", "team-b")

    def test_duplicate_teams_deduplicated(self) -> None:
        r = parse("* @acme/team-a\ndocs/ @acme/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_source_order_preserved(self) -> None:
        r = parse("* @acme/beta\ndocs/ @acme/alpha\n", "acme")
        assert r.team_slugs == ("beta", "alpha")

    def test_uppercase_team_slug_normalized_to_lowercase(self) -> None:
        # GitHub team slugs are always lowercase. An uppercase CODEOWNERS
        # entry must be normalized so the teams API is queried with the real
        # slug (lowercase) instead of 404-ing and denying a legitimate
        # codeowner.
        r = parse("* @acme/Team-A\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_mixed_case_same_team_deduplicated(self) -> None:
        # @acme/Team-A and @acme/team-a are the same team; after
        # normalization they must collapse to one slug (and one API call),
        # not two.
        r = parse("* @acme/Team-A\ndocs/ @acme/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)


class TestComments:
    """CODEOWNERS supports # comments both whole-line and inline."""

    def test_full_line_comment(self) -> None:
        r = parse("# just a comment\n* @acme/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_inline_comment(self) -> None:
        r = parse("* @acme/team-a  # this is the default owner\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_comment_only_file(self) -> None:
        r = parse("# only comments\n# another\n", "acme")
        assert r.team_slugs == ()

    def test_hash_inside_pattern_treated_as_comment(self) -> None:
        # Not strictly correct CODEOWNERS semantics but neither is a hash
        # in a pattern; being permissive-toward-comments is safer than
        # trying to distinguish.
        r = parse("*.txt #suffix @acme/team-a\n", "acme")
        assert r.team_slugs == ()


class TestSectionHeaders:
    """Section syntax added in 2022. See docs/authorship."""

    def test_bracketed_section_alone(self) -> None:
        # A pure section header with no default owners: no teams captured.
        r = parse("[section-name]\n* @acme/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_section_with_default_owners_captured(self) -> None:
        # Default owners on the header line ARE valid codeowners.
        r = parse("[section] @acme/team-b\n", "acme")
        assert r.team_slugs == ("team-b",)

    def test_optional_section_with_caret(self) -> None:
        # ^[section] is the "approvals optional" variant. Same team-capture
        # behavior.
        r = parse("^[optional] @acme/team-c\n", "acme")
        assert r.team_slugs == ("team-c",)

    def test_section_with_pattern_line_below(self) -> None:
        r = parse("[section] @acme/default\ndocs/ @acme/specific\n", "acme")
        assert r.team_slugs == ("default", "specific")

    def test_glob_character_class_not_mistaken_for_section(self) -> None:
        # Regression: ``[Cc]hangelog.md`` is a valid CODEOWNERS file pattern
        # (glob character class), NOT a section header. Without a trailing-
        # whitespace requirement on the section-header regex, the parser
        # would strip ``[Cc]`` and treat the remaining
        # ``hangelog.md @acme/docs-team`` as a section header with a default
        # owner — silently granting ``docs-team`` whole-repo authorization
        # when the maintainer intended file-scoped ownership.
        #
        # NOTE: this input alone doesn't distinguish pre-fix from post-fix
        # (both parsers end up with ``('docs-team',)`` for coincidental
        # reasons — see ``test_glob_wedge_case`` below for the actual
        # behavioral wedge that pins the fix).
        r = parse("[Cc]hangelog.md @acme/docs-team\n", "acme")
        assert r.team_slugs == ("docs-team",)

    def test_glob_wedge_case_pins_the_fix(self) -> None:
        # THIS is the test that fails on the buggy regex and passes on the
        # fixed one — the input where pre-fix and post-fix diverge.
        #
        # Input: ``[Cc]@acme/evil @acme/docs-team``
        #
        # Pre-fix regex ``^\s*\^?\[[^\]]+\]\s*`` matches ``[Cc]`` and strips
        # it. The parser then enters section-body mode, splits the remainder
        # into two owner tokens ``@acme/evil`` and ``@acme/docs-team``, and
        # captures BOTH → team_slugs == ('evil', 'docs-team'). The
        # attacker-controlled ``evil`` team is granted whole-repo
        # authorization on any repo whose CODEOWNERS accidentally contains
        # a leading glob character class.
        #
        # Post-fix regex ``^\s*\^?\[[^\]]+\](?=\s|$)`` does NOT match ``[Cc]``
        # because the ``]`` is not followed by whitespace-or-EOL. The parser
        # enters pattern-body mode, treating ``[Cc]@acme/evil`` as the file
        # pattern and ``@acme/docs-team`` as the sole owner → team_slugs ==
        # ('docs-team',).
        #
        # A future revert of the regex would flip this test red immediately.
        r = parse("[Cc]@acme/evil @acme/docs-team\n", "acme")
        assert r.team_slugs == ("docs-team",)
        assert "evil" not in r.team_slugs

    def test_glob_character_class_with_multiple_lines(self) -> None:
        # Broader realistic form. Same caveat as the first glob test — this
        # input doesn't distinguish the two parsers; both would emit both
        # teams. Kept for coverage of the multi-line path, not as a
        # regression pin. The wedge test above is what pins the fix.
        text = "docs/ @acme/docs-team\n[Cc]hangelog.md @acme/changelog-team\n"
        r = parse(text, "acme")
        assert set(r.team_slugs) == {"docs-team", "changelog-team"}

    def test_glob_with_only_glob_line_no_teams(self) -> None:
        # Bare glob line with no team owner. Pre-fix and post-fix both emit
        # ``()`` here for different reasons — not a wedge, kept purely to
        # document that a pattern-only line contributes no teams.
        r = parse("[Cc]hangelog.md\n", "acme")
        assert r.team_slugs == ()


class TestWhitespace:
    """Tabs and mixed whitespace are legal separators."""

    def test_tab_separators(self) -> None:
        r = parse("*\t@acme/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_leading_whitespace_ignored(self) -> None:
        r = parse("   * @acme/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_multiple_spaces_between_tokens(self) -> None:
        r = parse("*     @acme/team-a    @acme/team-b\n", "acme")
        assert r.team_slugs == ("team-a", "team-b")

    def test_empty_lines_ignored(self) -> None:
        r = parse("\n\n* @acme/team-a\n\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_windows_line_endings(self) -> None:
        r = parse("* @acme/team-a\r\ndocs/ @acme/team-b\r\n", "acme")
        assert r.team_slugs == ("team-a", "team-b")


class TestOrgFiltering:
    """Only same-org teams count. Cross-org teams are tracked separately."""

    def test_cross_org_team_not_in_team_slugs(self) -> None:
        r = parse("* @other-org/team-a\n", "acme")
        assert r.team_slugs == ()
        assert r.cross_org_teams == ("@other-org/team-a",)

    def test_case_insensitive_org_match(self) -> None:
        r = parse("* @ACME/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)

    def test_mixed_same_and_cross_org(self) -> None:
        r = parse("* @acme/local @other-org/external\n", "acme")
        assert r.team_slugs == ("local",)
        assert r.cross_org_teams == ("@other-org/external",)


class TestIndividualHandles:
    """Individual @user handles are tracked but not counted as team owners."""

    def test_individual_handle_recorded(self) -> None:
        r = parse("* @someuser\n", "acme")
        assert r.team_slugs == ()
        assert r.individuals == ("@someuser",)

    def test_mixed_individual_and_team(self) -> None:
        r = parse("* @someuser @acme/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)
        assert r.individuals == ("@someuser",)


class TestEmails:
    """Email owners are tracked but not counted."""

    def test_email_owner_recorded(self) -> None:
        r = parse("* owner@example.com\n", "acme")
        assert r.team_slugs == ()
        assert r.emails == ("owner@example.com",)

    def test_email_and_team_together(self) -> None:
        r = parse("* owner@example.com @acme/team-a\n", "acme")
        assert r.team_slugs == ("team-a",)
        assert r.emails == ("owner@example.com",)


class TestDegenerateInputs:
    """Empty, malformed, or non-standard inputs must fail closed."""

    def test_empty_file(self) -> None:
        r = parse("", "acme")
        assert r.team_slugs == ()
        assert r.individuals == ()
        assert r.emails == ()
        assert r.cross_org_teams == ()

    def test_only_whitespace(self) -> None:
        r = parse("   \n\t\n\n", "acme")
        assert r.team_slugs == ()

    def test_pattern_without_owner(self) -> None:
        # A pattern with no owner is legal CODEOWNERS syntax (means "no
        # required review"). No teams captured.
        r = parse("*.tmp\n", "acme")
        assert r.team_slugs == ()

    def test_garbage_owner_silently_dropped(self) -> None:
        # We prefer permissive parsing to hard rejection.
        r = parse("* not-a-valid-owner\n", "acme")
        assert r.team_slugs == ()

    def test_only_cross_org_teams(self) -> None:
        # This is the "helpful diagnostic" case: no local teams but we
        # captured cross-org so the maintainer can see what happened.
        r = parse("* @other-org/team\n", "acme")
        assert r.team_slugs == ()
        assert r.cross_org_teams == ("@other-org/team",)


class TestRealisticFiles:
    """Realistic CODEOWNERS files from the wild."""

    def test_kyma_companion_style(self) -> None:
        text = (
            "# Overview comment\n"
            "\n"
            "* @kyma-project/ai-force\n"
            "*.md @kyma-project/technical-writers\n"
            "/docs/ @kyma-project/technical-writers\n"
            "/.claude/ @kyma-project/ai-force\n"
            "CLAUDE.md @kyma-project/ai-force\n"
        )
        r = parse(text, "kyma-project")
        assert set(r.team_slugs) == {"ai-force", "technical-writers"}

    def test_with_section_headers_and_defaults(self) -> None:
        text = (
            "[core] @acme/core-team\n"
            "src/ @acme/core-team\n"
            "^[optional-review] @acme/reviewers\n"
            "docs/ @acme/docs\n"
        )
        r = parse(text, "acme")
        assert set(r.team_slugs) == {"core-team", "reviewers", "docs"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
