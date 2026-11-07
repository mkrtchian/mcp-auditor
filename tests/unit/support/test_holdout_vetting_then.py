def second_passes_ran_alone_after_every_first_pass(
    events: list[tuple[str, str]], first_passes: int
) -> None:
    first, second = events[: 2 * first_passes], events[2 * first_passes :]
    assert [kind for kind, _ in first].count("end") == first_passes
    assert second, "no second pass ran"
    for index in range(0, len(second), 2):
        (start, started), (end, ended) = second[index], second[index + 1]
        assert (start, end) == ("start", "end")
        assert started == ended, f"{started}'s second pass overlapped {ended}'s"
