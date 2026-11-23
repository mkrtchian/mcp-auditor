import argparse


def positive_int(text: str) -> int:
    return _at_least(text, 1)


def non_negative_int(text: str) -> int:
    return _at_least(text, 0)


def _at_least(text: str, minimum: int) -> int:
    try:
        count = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {text!r}") from None
    if count < minimum:
        raise argparse.ArgumentTypeError(f"expected at least {minimum}, got {count}")
    return count
