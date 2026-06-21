from __future__ import annotations

from packetforge.ui.help.topics import HELP_TOPICS, help_topic


def test_help_topics_cover_major_tabs() -> None:
    for key in (
        "discovery_center",
        "ping_lab",
        "network_map",
        "observability",
        "scapy_console",
        "global",
    ):
        topic = help_topic(key)
        assert topic.title
        assert topic.intro
        assert topic.sections


def test_unknown_help_key_falls_back_to_global() -> None:
    topic = help_topic("not_a_real_tab")
    assert topic.key == "global"


def test_all_registered_topics_have_content() -> None:
    for key, topic in HELP_TOPICS.items():
        assert topic.key == key
        assert topic.title.strip()
        assert topic.intro.strip()
        assert topic.sections
