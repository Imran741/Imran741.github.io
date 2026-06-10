"""Unit tests for entropy calculation and categorisation."""

import math

import pytest

from app.analyzers import entropy


class TestCharacterClassDetection:
    def test_lowercase_only(self):
        classes = entropy.detect_character_classes("abcdef")
        assert classes.lowercase
        assert not classes.uppercase
        assert not classes.digits
        assert not classes.special
        assert classes.pool_size() == 26

    def test_all_classes(self):
        classes = entropy.detect_character_classes("Abc123!@#")
        assert classes.lowercase and classes.uppercase
        assert classes.digits and classes.special
        assert classes.pool_size() == 26 + 26 + 10 + 32
        assert classes.count() == 4

    def test_digits_only(self):
        classes = entropy.detect_character_classes("123456")
        assert classes.pool_size() == 10

    def test_unicode_counts_as_special(self):
        classes = entropy.detect_character_classes("abcéµ")
        assert classes.special


class TestEntropyCalculation:
    def test_empty_password_is_zero(self):
        assert entropy.calculate_entropy("") == 0.0

    def test_lowercase_formula(self):
        # 8 lowercase chars: 8 * log2(26) ≈ 37.6
        expected = round(8 * math.log2(26), 2)
        assert entropy.calculate_entropy("abcdefgh") == expected

    def test_full_charset_formula(self):
        # 12 chars over a 94-symbol pool: 12 * log2(94) ≈ 78.66
        expected = round(12 * math.log2(94), 2)
        assert entropy.calculate_entropy("Ab1!Ab1!Ab1!") == expected

    def test_entropy_grows_with_length(self):
        assert entropy.calculate_entropy("abcdefgh") < entropy.calculate_entropy("abcdefghij")

    def test_entropy_grows_with_pool(self):
        assert entropy.calculate_entropy("abcdefgh") < entropy.calculate_entropy("abcdefG1")


class TestEntropyCategories:
    @pytest.mark.parametrize(
        ("bits", "category"),
        [
            (0, "Very Weak"),
            (27.9, "Very Weak"),
            (28, "Weak"),
            (35.9, "Weak"),
            (36, "Moderate"),
            (59.9, "Moderate"),
            (60, "Strong"),
            (127.9, "Strong"),
            (128, "Very Strong"),
            (500, "Very Strong"),
        ],
    )
    def test_thresholds(self, bits, category):
        assert entropy.categorize_entropy(bits) == category


class TestEntropyReport:
    def test_report_shape(self):
        report = entropy.entropy_report("Abc123!x")
        assert set(report) == {"bits", "category", "pool_size", "character_classes"}
        assert report["pool_size"] == 94
        assert report["character_classes"]["special"] is True

    def test_empty_password_report(self):
        report = entropy.entropy_report("")
        assert report["bits"] == 0.0
        assert report["category"] == "Very Weak"
        assert report["pool_size"] == 0
