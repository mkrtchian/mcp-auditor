from pathlib import Path

from tests.integration.committed.cve.support.test_committed_stand_ins_given import is_ip_literal


def each_leaf_names_exactly_one_of(leaves: dict[str, set[str]], hosts: set[str]) -> None:
    assert {name: names for name, names in leaves.items() if not names <= hosts} == {}
    assert all(len(names) == 1 for names in leaves.values())


def each_ip_literal_leaf_names_only_its_address(
    leaves: dict[str, set[str]], common_names: dict[str, list[str]]
) -> None:
    addresses = {name: Path(name).stem for name in leaves if is_ip_literal(Path(name).stem)}
    assert {name: leaves[name] for name in addresses} == {
        name: {address} for name, address in addresses.items()
    }
    assert {name: common_names[name] for name in addresses} == {name: [] for name in addresses}
