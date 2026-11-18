def runs_announced(announced: list[str], *, together: list[str], alone: list[str]) -> None:
    """Each run announced once as it finishes, the runs done rising from 1 to the total: the
    runs played together in any order, then the runs played alone in their order."""
    total = len(together) + len(alone)
    statuses = [line.rsplit(" [", 1)[0] for line in announced]
    progress = [line.rsplit(" [", 1)[1] for line in announced]
    assert progress == [f"{done}/{total} runs]" for done in range(1, total + 1)]
    assert sorted(statuses[: len(together)]) == sorted(together)
    assert statuses[len(together) :] == alone
