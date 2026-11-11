import pytest

import tests.unit.support.test_kit_driver_given as given
from evals.cve.kit.driver import TargetVersion, launch_user_condition, options_before_image

VULNERABLE = TargetVersion.VULNERABLE


@pytest.mark.parametrize("value", ["1000:1000", "0:0"])
def test_a_launch_running_as_another_account_is_an_out_of_calibration_reason(value: str):
    options = given.options_running_as("--user", value)

    assert launch_user_condition(VULNERABLE, options, given.a_spec()) == (
        f"vulnerable: the launch runs as {value}, not the unprivileged account"
    )


def test_a_launch_setting_no_user_is_an_out_of_calibration_reason():
    condition = launch_user_condition(
        TargetVersion.PATCHED, given.options_running_as(), given.a_spec()
    )

    assert condition == "patched: the launch sets no --user"


@pytest.mark.parametrize(
    "user_options",
    [
        ("--user", "65534:65534"),
        ("--user=65534:65534",),
        ("-u", "65534:65534"),
        ("-u=65534:65534",),
        ("-u65534:65534",),
    ],
)
def test_the_unprivileged_account_in_any_spelling_is_no_condition(user_options: tuple[str, ...]):
    options = given.options_running_as(*user_options)

    assert launch_user_condition(VULNERABLE, options, given.a_spec()) is None


def test_the_planted_account_is_no_condition():
    spec = given.a_spec_with_an_account()
    assert spec.account is not None
    options = given.options_running_as("--user", f"{spec.account.uid}:{spec.account.gid}")

    assert launch_user_condition(VULNERABLE, options, spec) is None


def test_the_last_of_several_user_options_wins():
    options = given.options_running_as("--user", "65534:65534", "-u=1000:1000")

    assert launch_user_condition(VULNERABLE, options, given.a_spec()) == (
        "vulnerable: the launch runs as 1000:1000, not the unprivileged account"
    )


def test_the_server_arguments_after_the_image_are_not_read_as_options():
    argv = [*given.options_running_as("--user", "65534:65534"), "img:local", "-u", "1000:1000"]

    options = options_before_image(argv, "img:local")

    assert "1000:1000" not in options
    assert launch_user_condition(VULNERABLE, options, given.a_spec()) is None
