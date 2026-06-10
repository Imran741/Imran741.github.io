"""Unit tests for the composite password scorer and pattern detection."""

import pytest

from app.analyzers import patterns, scoring


class TestComponentScores:
    def test_length_score_caps_at_max(self):
        assert scoring.length_score("a" * 16) == scoring.MAX_LENGTH_POINTS
        assert scoring.length_score("a" * 64) == scoring.MAX_LENGTH_POINTS

    def test_length_score_scales_linearly(self):
        assert scoring.length_score("a" * 8) == scoring.MAX_LENGTH_POINTS // 2

    def test_variety_score_full_credit(self):
        assert scoring.variety_score("Ab1!") == scoring.MAX_VARIETY_POINTS

    def test_variety_score_single_class(self):
        assert scoring.variety_score("abcd") == round(scoring.MAX_VARIETY_POINTS / 4)

    def test_empty_password_scores_zero(self):
        report = scoring.score_password("")
        assert report["score"] == 0
        assert report["label"] == "Very Weak"


class TestPenalties:
    def test_common_password_penalised(self):
        report = scoring.score_password("password")
        assert report["components"]["penalty"] >= scoring.PENALTY_COMMON_PASSWORD
        assert report["score"] < 20

    def test_clean_random_password_has_no_penalty(self):
        report = scoring.score_password("X7#mQ9$vL2@k")
        assert report["components"]["penalty"] == 0

    def test_repeated_pattern_penalised(self):
        clean = scoring.score_password("X7#mQ9$vL2@k")
        repeated = scoring.score_password("X7#mQ9aaa$vL")
        assert repeated["components"]["penalty"] > clean["components"]["penalty"]


class TestScoreBounds:
    @pytest.mark.parametrize(
        "password",
        ["password", "123456", "a", "Tr0ub4dour&3", "X7#mQ9$vL2@kP4!nW8^z", "aaaaaaaaaaaaaaaa"],
    )
    def test_score_always_in_range(self, password):
        score = scoring.score_password(password)["score"]
        assert 0 <= score <= 100

    def test_strong_password_scores_high(self):
        assert scoring.score_password("X7#mQ9$vL2@kP4!nW8^z")["score"] >= 80

    def test_weak_password_scores_low(self):
        assert scoring.score_password("abc123")["score"] <= 40

    def test_labels_match_thresholds(self):
        assert scoring.label_for_score(0) == "Very Weak"
        assert scoring.label_for_score(25) == "Weak"
        assert scoring.label_for_score(50) == "Moderate"
        assert scoring.label_for_score(70) == "Strong"
        assert scoring.label_for_score(95) == "Very Strong"


class TestPatternDetection:
    def test_common_password_detected(self):
        assert patterns.is_common_password("password")
        assert patterns.is_common_password("Password123")  # case + digit-strip

    def test_uncommon_password_not_flagged(self):
        assert not patterns.is_common_password("X7#mQ9$vL2@k")

    def test_dictionary_word_detected(self):
        found = patterns.find_dictionary_words("mydragonpass")
        assert "dragon" in found

    def test_longest_dictionary_match_wins(self):
        found = patterns.find_dictionary_words("sunshine42")
        assert "sunshine" in found
        assert "shine" not in found

    def test_repeated_single_char(self):
        assert "a" in patterns.find_repeated_patterns("xxaaayy")

    def test_repeated_unit(self):
        assert "abc" in patterns.find_repeated_patterns("abcabcabc")

    def test_sequential_alphabet_run(self):
        assert any("abc" in run for run in patterns.find_sequential_patterns("xabcdy"))

    def test_sequential_digits_reverse(self):
        assert patterns.find_sequential_patterns("x4321y")

    def test_keyboard_row_detected(self):
        assert any("qwert" in run for run in patterns.find_sequential_patterns("qwerty99"))

    def test_random_string_has_no_sequences(self):
        assert patterns.find_sequential_patterns("x9$k2#m7") == []
