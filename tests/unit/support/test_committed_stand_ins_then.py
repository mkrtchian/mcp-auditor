def each_leaf_names_exactly_one_of(leaves: dict[str, set[str]], hosts: set[str]) -> None:
    assert {name: names for name, names in leaves.items() if not names <= hosts} == {}
    assert all(len(names) == 1 for names in leaves.values())
