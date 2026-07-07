"""Tests for the name-parsing/resolution logic in consolidate_noncompliant.py -
historically the buggiest part of this pipeline (see git log: the CMDB
'Given Surname' vs AD 'Surname, Given' ordering bug, and the Terry-SP/Terry-CP
overlap-ranking bug were both real production bugs found by hand, not by
tests). These pin down the fixes so they can't silently regress.
"""
import consolidate_noncompliant as cnc


def make_ad(entries):
    """entries: list of (surname, given_str, email) -> an `ad` dict shaped
    like read_ad_users()'s return value, using structured Surname/GivenName
    (the common case for real exports)."""
    by_surname = {}
    for surname, given_str, email in entries:
        by_surname.setdefault(surname.lower(), []).append({
            "disp": f"{surname}, {given_str}",
            "email": email,
            "given": cnc.name_tokens(given_str),
        })
    return {"exact": {}, "by_surname": by_surname, "count": len(entries)}


# --- strip_external / norm_name / name_tokens ------------------------------

def test_strip_external_bracket_tag():
    clean, ext = cnc.strip_external("Lee, John Xavier [External]")
    assert ext is True
    assert "[External]" not in clean


def test_strip_external_paren_tag():
    clean, ext = cnc.strip_external("Smith, Jane (External)")
    assert ext is True


def test_strip_external_no_tag():
    clean, ext = cnc.strip_external("Chan, Terry-TM")
    assert ext is False
    assert clean == "Chan, Terry-TM"


def test_norm_name_ignores_extra_whitespace_and_case():
    assert cnc.norm_name("Chan,   Tai Man Terry") == cnc.norm_name("chan, tai man terry")


def test_name_tokens_splits_hyphen_and_period():
    assert cnc.name_tokens("Tai-Man.Terry") == {"tai", "man", "terry"}


def test_name_tokens_blank_or_none():
    assert cnc.name_tokens("") == set()
    assert cnc.name_tokens(None) == set()


# --- parse_name_variants -----------------------------------------------------

def test_comma_form_is_unambiguous():
    assert cnc.parse_name_variants("Chan, Tai Man Terry") == [("chan", ["tai", "man", "terry"])]


def test_comma_less_two_token_prefers_last_token_as_surname():
    """This is THE bug: CMDB's 'Assigned to' writes 'Given Surname' (e.g.
    'Vincent Lee'), not 'Surname Given'. The first variant tried must treat
    the LAST token as the surname."""
    variants = cnc.parse_name_variants("Vincent Lee")
    assert variants[0] == ("lee", ["vincent"])


def test_comma_less_multiword_surname_is_tried():
    """'Michele De Filippo' -> AD's real Surname is 'De Filippo' (two words).
    Some variant must try the two-word trailing chunk as the surname."""
    variants = cnc.parse_name_variants("Michele De Filippo")
    surnames_tried = [v[0] for v in variants]
    assert "de filippo" in surnames_tried


def test_single_token_name():
    assert cnc.parse_name_variants("Cher") == [("cher", [])]


def test_empty_name():
    assert cnc.parse_name_variants("") == [("", [])]


def test_parse_name_returns_first_variant():
    assert cnc.parse_name("Chan, Terry") == ("chan", ["terry"])


# --- resolve_name_to_email ---------------------------------------------------

def test_override_always_wins():
    ad = make_ad([("Lau", "Terry-SP", "terry-sp.lau@x.com")])
    overrides = {cnc.norm_name("Terry-SP Lau"): "manual-pick@x.com"}
    email, method, conf, cands = cnc.resolve_name_to_email("Terry-SP Lau", ad, overrides)
    assert (email, method, conf) == ("manual-pick@x.com", "override", "high")


def test_exact_name_match():
    ad = {"exact": {cnc.norm_name("Wong, Siu Ming"): "siuming.wong@x.com"},
          "by_surname": {}, "count": 1}
    email, method, conf, cands = cnc.resolve_name_to_email("Wong, Siu Ming", ad, {})
    assert (email, method, conf) == ("siuming.wong@x.com", "exact name", "high")


def test_comma_form_unique_heuristic_match():
    ad = make_ad([("Chan", "Terry", "terry.chan@x.com")])
    email, method, conf, cands = cnc.resolve_name_to_email("Chan, Tai Man Terry", ad, {})
    assert email == "terry.chan@x.com"
    assert conf == "medium"


def test_comma_less_given_surname_resolves_correctly():
    """Regression: 'Vincent Lee' must resolve against AD's Surname='Lee',
    GivenName='Vincent' - it used to look up surname bucket 'vincent' and
    silently fail to match anything."""
    ad = make_ad([("Lee", "Vincent", "vincent.lee@x.com")])
    email, method, conf, cands = cnc.resolve_name_to_email("Vincent Lee", ad, {})
    assert email == "vincent.lee@x.com"


def test_comma_less_multiword_surname_resolves_correctly():
    ad = make_ad([("De Filippo", "Michele", "michele.defilippo@x.com")])
    email, method, conf, cands = cnc.resolve_name_to_email("Michele De Filippo", ad, {})
    assert email == "michele.defilippo@x.com"


def test_overlap_ranking_prefers_fuller_match_over_partial():
    """The exact real-world bug: 'Terry-SP Lau' -> tokens {terry, sp}. AD has
    both 'Lau, Terry' ({terry}, partial) and 'Lau, Terry-SP' ({terry, sp},
    full). The fuller match must win outright, not get flagged as tied."""
    ad = make_ad([
        ("Lau", "Terry", "terry-cp.lau@x.com"),
        ("Lau", "Terry-SP", "terry-sp.lau@x.com"),
    ])
    email, method, conf, cands = cnc.resolve_name_to_email("Terry-SP Lau", ad, {})
    assert email == "terry-sp.lau@x.com"
    assert conf == "medium"


def test_genuine_tie_goes_to_review_not_guessed():
    """Two real, distinct people both literally 'Nick Lee' (same given+surname
    overlap) - must NOT auto-resolve to either; goes to review with both
    candidates listed."""
    ad = make_ad([
        ("Lee", "Nick", "nick.ca.lee@x.com"),
        ("Lee", "Nick", "nick.s.lee@x.com"),
    ])
    email, method, conf, cands = cnc.resolve_name_to_email("Nick Lee", ad, {})
    assert email is None
    assert conf == "low"
    assert set(cands) == {"nick.ca.lee@x.com", "nick.s.lee@x.com"}


def test_surname_only_match_no_given_overlap_goes_to_review():
    ad = make_ad([("Smith", "Robert", "robert.smith@x.com")])
    email, method, conf, cands = cnc.resolve_name_to_email("John Smith", ad, {})
    assert email is None
    assert conf == "low"
    assert cands == ["robert.smith@x.com"]


def test_no_ad_match_at_all():
    ad = {"exact": {}, "by_surname": {}}
    email, method, conf, cands = cnc.resolve_name_to_email("Nobody Here", ad, {})
    assert email is None
    assert conf == "none"
