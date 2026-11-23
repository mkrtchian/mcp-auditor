import argparse

import pytest

from evals.cli_arguments import non_negative_int, positive_int


def test_a_count_below_one_is_refused_as_an_argument():
    with pytest.raises(argparse.ArgumentTypeError):
        positive_int("0")


def test_a_non_integer_is_refused_as_an_argument():
    with pytest.raises(argparse.ArgumentTypeError):
        positive_int("many")


def test_a_positive_count_is_accepted_as_an_argument():
    assert positive_int("3") == 3


def test_zero_is_accepted_and_a_negative_count_refused_where_none_is_allowed():
    assert non_negative_int("0") == 0
    with pytest.raises(argparse.ArgumentTypeError, match="expected at least 0, got -1"):
        non_negative_int("-1")
