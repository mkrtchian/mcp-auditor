import ast

from evals.honeypots import HONEYPOTS


def test_no_honeypot_passes_instructions_to_its_server():
    for honeypot in HONEYPOTS:
        module = ast.parse(honeypot.server.read_text())

        assert not any(
            isinstance(node, ast.keyword) and node.arg == "instructions"
            for node in ast.walk(module)
        ), honeypot.name


def test_no_tool_name_appears_in_two_honeypots():
    tool_names = [{tool for tool, _ in honeypot.ground_truth} for honeypot in HONEYPOTS]

    assert len(set[str]().union(*tool_names)) == sum(len(names) for names in tool_names)
