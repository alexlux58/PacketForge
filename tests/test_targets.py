from packetforge.engine.targets import (
    estimate_count,
    expand_token,
    is_local_subnet,
    parse_targets,
    preview_targets,
    validate_host_token,
)


def test_parse_single_host() -> None:
    result = parse_targets("192.168.1.10")
    assert result.targets == ["192.168.1.10"]
    assert result.count == 1


def test_parse_cidr_expands_usable_hosts() -> None:
    result = parse_targets("192.168.1.0/30")
    # /30 -> 4 addresses, 2 usable hosts
    assert result.targets == ["192.168.1.1", "192.168.1.2"]


def test_parse_slash_31_includes_both_addresses() -> None:
    assert expand_token("10.0.0.0/31") == ["10.0.0.0", "10.0.0.1"]


def test_parse_slash_32_single_host() -> None:
    assert expand_token("10.0.0.5/32") == ["10.0.0.5"]


def test_parse_last_octet_range() -> None:
    result = parse_targets("192.168.1.10-12")
    assert result.targets == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]


def test_parse_full_dashed_range() -> None:
    result = parse_targets("10.0.0.254-10.0.1.1")
    assert result.targets == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]


def test_parse_mixed_tokens_and_dedup() -> None:
    result = parse_targets("192.168.1.1, 192.168.1.1 192.168.1.2\nhost.lab.example")
    assert result.targets == ["192.168.1.1", "192.168.1.2", "host.lab.example"]


def test_invalid_tokens_are_skipped_with_warning() -> None:
    result = parse_targets("192.168.1.1, not-an-ip!, 999.999.1.1")
    assert "192.168.1.1" in result.targets
    assert result.skipped == ["not-an-ip!", "999.999.1.1"]
    assert result.warnings


def test_range_end_before_start_is_invalid() -> None:
    result = parse_targets("10.0.0.10-5")
    assert result.targets == []
    assert result.skipped == ["10.0.0.10-5"]


def test_truncation_respects_max_targets() -> None:
    result = parse_targets("10.0.0.0/24", max_targets=10)
    assert result.count == 10
    assert result.truncated is True
    assert any("truncated" in warning.lower() for warning in result.warnings)


def test_large_cidr_preview_stops_early() -> None:
    result = parse_targets("10.0.0.0/8", max_targets=10)
    assert result.count == 10
    assert result.truncated is True


def test_partial_target_while_typing_is_fast() -> None:
    result = preview_targets("192.168.4.")
    assert result.count == 0
    assert result.skipped


def test_estimate_count_matches_parse() -> None:
    assert estimate_count("192.168.0.0/24") == 254


def test_is_local_subnet() -> None:
    assert is_local_subnet("192.168.1.0/24") is True
    assert is_local_subnet("10.0.0.5") is True
    assert is_local_subnet("8.8.8.8") is False


def test_validate_host_token_accepts_ip_and_hostname() -> None:
    assert validate_host_token("192.168.1.1") == (True, "")
    assert validate_host_token("router.lab.example") == (True, "")


def test_validate_host_token_rejects_empty_and_garbage() -> None:
    ok, message = validate_host_token("")
    assert ok is False
    assert "Enter" in message
    ok, message = validate_host_token("not-an-ip!")
    assert ok is False
    assert "Invalid" in message
