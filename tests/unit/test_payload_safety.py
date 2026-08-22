from mcp_auditor.domain.payload_safety import DESTRUCTIVE_CONSTRUCTS, destructive_reason


def test_blocks_recursive_delete():
    assert destructive_reason({"command": "rm -rf /"}) == "destructive filesystem command: rm -rf"


def test_blocks_move_from_an_absolute_path():
    assert (
        destructive_reason({"cmd": "mv /data /data.bak"}) == "destructive filesystem command: mv /"
    )


def test_blocks_redirect_over_an_absolute_path():
    assert (
        destructive_reason({"cmd": "echo x > /etc/hosts"})
        == "output redirect overwriting a file: > /"
    )


def test_blocks_recursive_permission_change():
    assert (
        destructive_reason({"cmd": "chmod -R 000 /work"}) == "recursive permission change: chmod -r"
    )


def test_blocks_filesystem_creation():
    assert destructive_reason({"cmd": "mkfs.ext4 /dev/sda"}) == "destructive disk operation: mkfs."


def test_blocks_raw_device_write():
    assert destructive_reason({"cmd": "dd of=/dev/sda"}) == "destructive disk operation: dd of="


def test_blocks_drop_table():
    assert (
        destructive_reason({"query": "DROP TABLE users"}) == "destructive SQL statement: drop table"
    )


def test_blocks_truncate_table():
    assert (
        destructive_reason({"query": "TRUNCATE TABLE users"})
        == "destructive SQL statement: truncate table"
    )


def test_blocks_delete_from():
    assert (
        destructive_reason({"query": "'; DELETE FROM users--"})
        == "destructive SQL statement: delete from "
    )


def test_blocks_forced_push():
    assert (
        destructive_reason({"cmd": "git push --force"})
        == "forced version-control write: push --force"
    )


def test_blocks_shutdown_with_an_argument():
    assert destructive_reason({"cmd": "shutdown -h now"}) == "host availability command: shutdown -"


def test_blocks_fork_bomb():
    assert destructive_reason({"cmd": ":(){ :|:& };:"}) == "fork bomb: :(){"


def test_matching_is_case_insensitive():
    lowercase = destructive_reason({"query": "drop table users"})
    uppercase = destructive_reason({"query": "DROP TABLE users"})
    assert lowercase == uppercase == "destructive SQL statement: drop table"


def test_every_pattern_is_lowercase_and_not_a_bare_word():
    for construct in DESTRUCTIVE_CONSTRUCTS:
        for pattern in construct.patterns:
            assert pattern == pattern.lower(), f"{pattern!r} could never fire"
            assert not pattern.isalnum(), f"{pattern!r} would match incidental words"


def test_allows_a_redirect_to_a_harmless_sink_with_a_space():
    assert destructive_reason({"cmd": "cat log 2> /dev/null"}) is None


def test_allows_a_redirect_to_a_harmless_sink_without_a_space():
    assert destructive_reason({"cmd": "cat log 2>/dev/null"}) is None


def test_allows_injection_syntax():
    assert destructive_reason({"q": "' OR '1'='1"}) is None
    assert destructive_reason({"q": "; SELECT sqlite_version()"}) is None
    assert destructive_reason({"q": "$(id)"}) is None
    assert destructive_reason({"q": "`whoami`"}) is None
    assert destructive_reason({"q": "../../etc/passwd"}) is None
    assert destructive_reason({"q": "UNION SELECT null, null"}) is None
    assert destructive_reason({"q": "echo mcp-auditor-probe"}) is None


def test_allows_writes():
    assert destructive_reason({"repo_path": "/out/of/scope"}) is None
    assert destructive_reason({"files": ["."]}) is None
    assert destructive_reason({"path": "/tmp/x.txt", "content": "; echo marker"}) is None


def test_a_bare_greater_than_is_not_a_redirect():
    assert destructive_reason({"query": "WHERE price > 5"}) is None
    assert destructive_reason({"body": "<script>alert(1)</script>"}) is None
    assert destructive_reason({"cmd": "> /etc/hosts"}) is not None


def test_known_permitted_relative_path_redirect():
    assert destructive_reason({"cmd": "echo evil > notes.txt"}) is None


def test_known_permitted_bare_command_words():
    assert destructive_reason({"cmd": "shutdown"}) is None
    assert destructive_reason({"cmd": "reboot"}) is None


def test_known_permitted_move_from_a_relative_path():
    assert destructive_reason({"cmd": "mv notes.txt /tmp/"}) is None


def test_known_permitted_word_containing_halt():
    assert destructive_reason({"path": "/opt/halted"}) is None


def test_allows_a_legitimate_record_id():
    assert destructive_reason({"record_id": 1}) is None


def test_blocks_a_destructive_command_injected_into_a_record_id():
    assert (
        destructive_reason({"record_id": "1; rm -rf /"}) == "destructive filesystem command: rm -rf"
    )


def test_walks_into_lists():
    assert (
        destructive_reason({"items": ["ok", "rm -rf /"]})
        == "destructive filesystem command: rm -rf"
    )


def test_walks_into_nested_dicts():
    assert (
        destructive_reason({"outer": {"inner": {"cmd": "rm -rf /"}}})
        == "destructive filesystem command: rm -rf"
    )


def test_argument_names_are_never_inspected():
    assert destructive_reason({"rm -rf /": "hello"}) is None


def test_allows_empty_arguments():
    assert destructive_reason({}) is None


def test_allows_non_string_values():
    assert destructive_reason({"n": 1, "flag": True, "x": None}) is None


def test_allows_a_runlevel_digit_continuing_into_another_token():
    assert destructive_reason({"cmd": "git init 0auth"}) is None
    assert destructive_reason({"cmd": "kill -9 1234"}) is None


def test_known_permitted_false_block_inside_a_longer_word():
    # "rm /" and "rm ~" carry no left delimiter, so they fire mid-word. Blocking a harmless
    # value costs recall, requiring a left boundary would let "%3Brm -rf /" through.
    assert destructive_reason({"cmd": "perform /admin"}) is not None
    assert destructive_reason({"cmd": "transform ~/data"}) is not None


def test_still_blocks_a_construct_reached_through_an_encoded_separator():
    assert destructive_reason({"cmd": "%3Brm -rf /"}) == "destructive filesystem command: rm -rf"
    assert destructive_reason({"cmd": "telinit 0"}) == "host availability command: init 0"


def test_still_blocks_a_pattern_preceded_by_a_shell_delimiter():
    assert destructive_reason({"cmd": "rm /etc/passwd"}) == "destructive filesystem command: rm /"
    assert destructive_reason({"cmd": "ls; rm /etc"}) == "destructive filesystem command: rm /"
    assert destructive_reason({"cmd": "$(rm -rf /)"}) == "destructive filesystem command: rm -rf"
    assert destructive_reason({"cmd": "ls&&rm ~/x"}) == "destructive filesystem command: rm ~"
