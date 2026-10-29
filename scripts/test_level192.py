"""Independent rational checks for the experimental numerical screening model."""
from fractions import Fraction
from math import comb
import unittest
from unittest.mock import patch

import level192 as model


class CoverModelTests(unittest.TestCase):
    def assert_encloses(self, interval, exact):
        self.assertLessEqual(Fraction(interval.lo), exact)
        self.assertGreaterEqual(Fraction(interval.hi), exact)

    def test_interval_arithmetic_encloses_exact_rationals(self):
        for numerator, denominator in [(1, 3), (7, 11), (1, 2**192), (2**80+1, 97)]:
            exact = Fraction(numerator, denominator)
            bounded = model.Interval(numerator) / model.Interval(denominator)
            self.assert_encloses(bounded, exact)
            self.assert_encloses(bounded + bounded, exact * 2)
            self.assert_encloses(bounded * bounded, exact**2)
            self.assert_encloses(bounded**37, exact**37)

    def test_forest_one_reuse_retains_codeword_multiplicities(self):
        words = model.forest_table.table()
        # Equal-sum words cover each other only when identical. Enumerate digest entries,
        # including repeated entries, rather than using the production finite differences.
        same_word = Fraction(sum(a == b for a in words for b in words), 256**2)
        one_coordinate = Fraction(1, 16) * (same_word / 8)**2
        self.assert_encloses(model.conditional_cover()["forest"][1], one_coordinate**12)

    def test_fors_and_pruning_match_exact_binomial_sum(self):
        for h, b in [(20, 8), (20, 20), (28, 14)]:
            for signatures in [0, 1, 2, 5]:
                p = Fraction(1, 2**b)
                exact = sum(comb(signatures, r) * p**r * (1-p)**(signatures-r)
                            * (1-Fraction(1023, 1024)**r)**37
                            for r in range(signatures+1)) / 2**(h-b)
                self.assert_encloses(model.cover_probability("fors", h, b, signatures), exact)

    def test_occupancy_tail_is_retained(self):
        # Force a short sum: every positive occupancy covers, so the exact result is known.
        table = {"test": [model.Interval(0), model.Interval(1), model.Interval(1)]}
        with patch.object(model, "MAX_HITS", 2), patch.object(model, "conditional_cover", return_value=table):
            self.assert_encloses(model.cover_probability("test", 4, 4, 10),
                                 1-Fraction(15, 16)**10)

    def test_signature_sizes_match_independent_field_counts(self):
        for h in model.HEIGHTS:
            for shape, layers in [("pruned", 1), ("layered", 3)]:
                for variant, values in [("forest", 12*(2*(6+3)+4)), ("fors", 37*(1+10))]:
                    expected = 24 + 24*values + layers*(4+96*24) + h*24
                    self.assertEqual(model.signature_size(variant, h, shape), expected)


if __name__ == "__main__":
    unittest.main()
