import tests.unit.support.test_fixture_contamination_given as given
import tests.unit.support.test_fixture_contamination_then as then


class TestShippedConstantsNameNoHoneypotLiteral:
    def test_the_honeypots_plant_discriminating_literals(self):
        literals = given.discriminating_literals()

        assert {"Invalid category", "Alice"} <= literals

    def test_no_constant_of_src_contains_a_honeypot_literal(self):
        constants = given.shipped_constants()
        literals = given.discriminating_literals()

        then.no_constant_contains_any_of(constants, literals)
