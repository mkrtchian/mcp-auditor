import tests.unit.project.support.test_code_standards_scan_given as given
from tests.unit.project.support.code_standards_scan import CodeStandard, violations

NEWSPAPER = CodeStandard.NEWSPAPER_ORDER
FOREIGN = CodeStandard.FOREIGN_GIVEN_THEN
SETATTR = CodeStandard.MONKEYPATCH_SETATTR


def test_a_helper_above_its_only_caller_is_out_of_order():
    source = given.a_source(
        """
        def _helper():
            return 1

        def caller():
            return _helper()
        """
    )

    assert given.found(source) == [(NEWSPAPER, "_helper")]


def test_a_helper_below_its_caller_is_in_order():
    source = given.a_source(
        """
        def caller():
            return _helper()

        def _helper():
            return 1
        """
    )

    assert given.found(source) == []


def test_a_helper_with_a_caller_above_it_is_in_order():
    source = given.a_source(
        """
        def first():
            return _helper()

        def _helper():
            return 1

        def second():
            return _helper()
        """
    )

    assert given.found(source) == []


def test_a_helper_a_decorator_uses_is_in_order():
    source = given.a_source(
        """
        def _decorate(function):
            return function

        @_decorate
        def caller():
            return _decorate
        """
    )

    assert given.found(source) == []


def test_a_helper_an_argument_default_uses_is_in_order():
    source = given.a_source(
        """
        def _default():
            return 1

        def caller(value=_default()):
            return _default()
        """
    )

    assert given.found(source) == []


def test_a_helper_a_class_body_uses_is_in_order():
    source = given.a_source(
        """
        def _default():
            return 1

        class Settings:
            value = _default()

            def method(self):
                return _default()
        """
    )

    assert given.found(source) == []


def test_a_helper_module_level_code_uses_is_in_order():
    source = given.a_source(
        """
        def _build():
            return 1

        def caller():
            return _build()

        VALUE = _build()
        """
    )

    assert given.found(source) == []


def test_a_helper_a_type_checking_block_uses_is_in_order():
    source = given.a_source(
        """
        from typing import TYPE_CHECKING

        def _name():
            return 1

        def caller():
            return _name()

        if TYPE_CHECKING:
            _name()
        """
    )

    assert given.found(source) == []


def test_a_helper_only_a_later_method_uses_is_out_of_order():
    source = given.a_source(
        """
        def _helper():
            return 1

        class User:
            def method(self):
                return _helper()
        """
    )

    assert given.found(source) == [(NEWSPAPER, "_helper")]


def test_a_class_above_its_users_is_in_order():
    source = given.a_source(
        """
        class Value:
            pass

        def build():
            return Value()
        """
    )

    assert given.found(source) == []


def test_a_later_function_with_a_local_of_the_same_name_is_no_user():
    source = given.a_source(
        """
        def name():
            return 1

        def later(items):
            name = items[0]
            return name

        def other(name):
            return name
        """
    )

    assert given.found(source) == []


def test_a_method_is_never_checked():
    source = given.a_source(
        """
        class Service:
            def _helper(self):
                return 1

            def caller(self):
                return self._helper()
        """
    )

    assert given.found(source) == []


def test_an_unused_function_is_in_order():
    source = given.a_source(
        """
        def entry_point():
            return 1
        """
    )

    assert given.found(source) == []


def test_a_newspaper_violation_reports_the_line_of_the_function():
    source = given.a_source(
        """
        def _helper():
            return 1

        def caller():
            return _helper()
        """
    )

    assert [violation.line for violation in violations(source)] == [2]


def test_a_test_importing_its_own_given_and_then_passes():
    source = given.a_source(
        """
        import tests.unit.area.support.test_thing_given as given
        import tests.unit.area.support.test_thing_then as then
        """,
        path="tests/unit/area/test_thing.py",
    )

    assert given.found(source) == []


def test_a_then_importing_its_given_passes():
    source = given.a_source(
        """
        from tests.unit.area.support.test_thing_given import a_value
        """,
        path="tests/unit/area/support/test_thing_then.py",
    )

    assert given.found(source) == []


def test_a_test_importing_another_tests_given_as_a_module_is_foreign():
    source = given.a_source(
        """
        import tests.unit.area.support.test_other_given as other
        """,
        path="tests/unit/area/test_thing.py",
    )

    assert given.found(source) == [(FOREIGN, "test_other_given")]


def test_a_test_importing_another_tests_given_from_its_package_is_foreign():
    source = given.a_source(
        """
        from tests.unit.area.support import test_other_given
        """,
        path="tests/unit/area/test_thing.py",
    )

    assert given.found(source) == [(FOREIGN, "test_other_given")]


def test_a_test_importing_a_name_from_another_tests_then_is_foreign():
    source = given.a_source(
        """
        from tests.unit.area.support.test_other_then import it_holds
        """,
        path="tests/unit/area/test_thing.py",
    )

    assert given.found(source) == [(FOREIGN, "test_other_then")]


def test_a_given_importing_another_given_is_foreign():
    source = given.a_source(
        """
        import tests.unit.area.support.test_other_given as other
        """,
        path="tests/unit/area/support/test_thing_given.py",
    )

    assert given.found(source) == [(FOREIGN, "test_other_given")]


def test_a_shared_support_module_importing_a_given_is_foreign():
    source = given.a_source(
        """
        from tests.unit.area.support.test_thing_given import a_value
        """,
        path="tests/unit/support/shared_builders.py",
    )

    assert given.found(source) == [(FOREIGN, "test_thing_given")]


def test_a_module_outside_the_tests_may_import_a_given():
    source = given.a_source(
        """
        import tests.unit.area.support.test_thing_given as given
        """,
        path="evals/cve/module.py",
    )

    assert given.found(source) == []


def test_a_monkeypatch_setattr_on_a_module_attribute_is_reported():
    source = given.a_source(
        """
        def test_something(monkeypatch):
            monkeypatch.setattr(subprocess, "run", fake_run)
        """,
        path="tests/unit/area/test_thing.py",
    )

    assert given.found(source) == [(SETATTR, "test_something:subprocess.run")]


def test_a_monkeypatch_setattr_in_a_method_names_its_class():
    source = given.a_source(
        """
        class TestThing:
            def test_something(self, monkeypatch):
                monkeypatch.setattr(module.Service, "call", fake_call)
        """,
        path="tests/unit/area/test_thing.py",
    )

    assert given.found(source) == [(SETATTR, "TestThing:module.Service.call")]


def test_a_monkeypatch_setenv_is_allowed():
    source = given.a_source(
        """
        def test_something(monkeypatch):
            monkeypatch.setenv("HOME", "/tmp")
            monkeypatch.delenv("PATH")
        """,
        path="tests/unit/area/test_thing.py",
    )

    assert given.found(source) == []
