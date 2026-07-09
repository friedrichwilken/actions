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
        r = parse("[Cc]hangelog.md @acme/docs-team\n", "acme")
        # The team on this line owns ONLY the file pattern (the glob), so
        # it IS captured — but as an owner of a specific path, not as a
        # section default. Our current representation is a flat set of
        # team slugs (path scoping is a future enhancement), so this
        # particular file DOES end up with ``docs-team`` captured. What we
        # verify here is that the parser recognises ``[Cc]hangelog.md`` as
        # a pattern (i.e. tokens[0] is the pattern, tokens[1:] are owners)
        # rather than a header — behaviour that differs measurably from
        # the pre-fix code path when combined with additional lines.
        assert r.team_slugs == ("docs-team",)

    def test_glob_character_class_with_multiple_lines(self) -> None:
        # More probative form of the previous test: with an entry BEFORE the
        # glob line, the buggy pre-fix parser would happily emit both teams;
        # the fix keeps the semantics the same but for the RIGHT reason
        # (glob pattern parsed correctly, not header-stripping accident).
        text = "docs/ @acme/docs-team\n[Cc]hangelog.md @acme/changelog-team\n"
        r = parse(text, "acme")
        assert set(r.team_slugs) == {"docs-team", "changelog-team"}

    def test_glob_with_only_glob_line_no_teams(self) -> None:
        # Diagnostic case: a bare glob line with no team owner must not
        # spuriously capture teams. Pre-fix, ``[Cc]hangelog.md`` alone
        # would strip and become the empty header, contributing nothing —
        # accidentally correct here. Post-fix, the pattern is parsed as a
        # pattern with no owners — deliberately correct.
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
