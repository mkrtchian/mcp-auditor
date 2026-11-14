import pytest

from mcp_auditor.domain.redaction import Redaction
from mcp_auditor.domain.relayed_environment import (
    RelayedEnvironment,
    RelayRefusedError,
    RelayRequest,
)

_ENVIRON = {"TOKEN": "s3cr3t-t0ken-value", "PIN": "1234", "EMPTY": "", "REGION": "eu-west-1"}


def _resolved(redacted: tuple[str, ...] = (), plain: tuple[str, ...] = ()) -> RelayedEnvironment:
    return RelayedEnvironment.resolved(RelayRequest(redacted=redacted, plain=plain), _ENVIRON)


@pytest.mark.parametrize(
    ("redacted", "plain", "expected_message"),
    [
        (("TOKEN=abc",), (), "export TOKEN and pass --env TOKEN, or use --env-plain"),
        (("1BAD",), (), "1BAD is not a variable name"),
        ((), ("1BAD=x",), "1BAD is not a variable name"),
        (("MISSING",), (), "MISSING is not set in your environment"),
        ((), ("MISSING",), "MISSING is not set in your environment"),
        (("EMPTY",), (), "an empty value cannot be redacted"),
        (("TOKEN", "TOKEN"), (), "TOKEN is named twice"),
        (("TOKEN",), ("TOKEN",), "TOKEN is named twice"),
        ((), ("REGION", "REGION=x"), "REGION is named twice"),
    ],
)
def test_refuses_a_relay_it_cannot_honor(
    redacted: tuple[str, ...], plain: tuple[str, ...], expected_message: str
):
    with pytest.raises(RelayRefusedError, match=expected_message):
        _resolved(redacted, plain)


def test_refusing_env_name_value_does_not_echo_the_value():
    with pytest.raises(RelayRefusedError) as refusal:
        _resolved(redacted=("TOKEN=abc",))

    assert "--env TOKEN" in str(refusal.value)
    assert "abc" not in str(refusal.value)


def test_plain_value_given_inline_is_relayed_even_when_unset():
    relayed = _resolved(plain=("ZONE=eu-west-1a",))

    assert relayed.values == {"ZONE": "eu-west-1a"}


def test_plain_value_splits_on_the_first_equal_sign():
    assert _resolved(plain=("X=a=b",)).values == {"X": "a=b"}


def test_plain_value_read_from_the_environment():
    assert _resolved(plain=("REGION",)).values == {"REGION": "eu-west-1"}


def test_empty_plain_value_is_accepted():
    assert _resolved(plain=("EMPTY",)).values == {"EMPTY": ""}


def test_names_list_the_redacted_ones_first_then_the_plain_ones():
    relayed = _resolved(redacted=("TOKEN", "PIN"), plain=("REGION",))

    assert relayed.names == ("TOKEN", "PIN", "REGION")


def test_names_keep_the_redacted_ones_first_whatever_the_argument_order():
    relayed = RelayedEnvironment.resolved(
        RelayRequest(plain=("REGION",), redacted=("TOKEN",)), _ENVIRON
    )

    assert relayed.names == ("TOKEN", "REGION")


def test_values_merge_both_kinds():
    relayed = _resolved(redacted=("TOKEN",), plain=("REGION",))

    assert relayed.values == {"TOKEN": "s3cr3t-t0ken-value", "REGION": "eu-west-1"}


def test_redaction_holds_the_redacted_values_only():
    relayed = _resolved(redacted=("TOKEN",), plain=("REGION",))

    assert relayed.redaction() == Redaction({"TOKEN": "s3cr3t-t0ken-value"})


def test_nothing_relayed_redacts_nothing():
    assert not RelayedEnvironment().redaction().active


def test_warns_about_a_short_redacted_value():
    assert _resolved(redacted=("PIN",)).warnings() == (
        "the value of PIN is 4 characters long: every occurrence of it in the server's "
        "output is replaced, including where it has nothing to do with the variable",
    )


@pytest.mark.parametrize("name", ["API_KEY", "api_key"])
def test_warns_about_a_plain_name_that_looks_like_a_secret(name: str):
    assert _resolved(plain=(f"{name}=x",)).warnings() == (
        f"{name} looks like a secret and --env-plain records its value in the report: "
        f"pass --env {name} to redact it",
    )


def test_warnings_follow_the_option_order():
    warnings = _resolved(redacted=("PIN",), plain=("API_KEY=x",)).warnings()

    assert [warning.split()[0:4] for warning in warnings] == [
        ["the", "value", "of", "PIN"],
        ["API_KEY", "looks", "like", "a"],
    ]


def test_no_warning_for_a_long_value_or_a_plain_name_that_is_not_a_secret():
    relayed = RelayedEnvironment.resolved(
        RelayRequest(redacted=("EIGHT",), plain=("REGION",)),
        {"EIGHT": "12345678", "REGION": "eu-west-1"},
    )

    assert relayed.warnings() == ()
