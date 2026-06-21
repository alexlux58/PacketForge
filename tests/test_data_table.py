"""DataTable widget tests — sort keys must never corrupt the displayed text."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

pytest.importorskip("PySide6.QtWidgets")

from packetforge.ui.widgets.data_table import _numeric_sort_key

# --- pure sort-key logic (no Qt needed) ------------------------------------


def test_numeric_sort_key_multi_value_port_list() -> None:
    # The bug: "22,80,8080" was mangled into the integer 22808080. It must now be
    # a per-element tuple so it sorts sensibly and the text stays intact.
    assert _numeric_sort_key("22,80,8080") == (22.0, 80.0, 8080.0)


def test_numeric_sort_key_single_and_suffixed_numbers() -> None:
    assert _numeric_sort_key("443") == (443.0,)
    assert _numeric_sort_key("4.2 ms") == (4.2,)
    assert _numeric_sort_key("0.85") == (0.85,)


def test_numeric_sort_key_non_numeric_is_text() -> None:
    assert _numeric_sort_key("icmp,tcp") is None
    assert _numeric_sort_key("tcp") is None
    assert _numeric_sort_key("") is None


# --- widget behaviour (needs a QApplication) -------------------------------


def _gui_runtime_available() -> bool:
    script = textwrap.dedent(
        """
        import os
        from pathlib import Path
        import PySide6
        from PySide6.QtCore import QCoreApplication
        from PySide6.QtWidgets import QApplication

        plugins = str(Path(PySide6.__file__).resolve().parent / "Qt" / "plugins")
        QCoreApplication.setLibraryPaths([plugins])
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = QApplication([])
        print("ok")
        app.quit()
        """
    ).lstrip()
    env = os.environ.copy()
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=20, env=env
    )
    return result.returncode == 0 and "ok" in result.stdout


pytestmark = pytest.mark.skipif(
    not _gui_runtime_available(),
    reason="Qt platform plugins unavailable in this environment",
)


@pytest.fixture(scope="module")
def qapp():  # type: ignore[no-untyped-def]
    from pathlib import Path

    import PySide6
    from PySide6.QtCore import QCoreApplication
    from PySide6.QtWidgets import QApplication

    plugins = str(Path(PySide6.__file__).resolve().parent / "Qt" / "plugins")
    QCoreApplication.setLibraryPaths([plugins])
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    yield app


def _two_row_table():  # type: ignore[no-untyped-def]
    from packetforge.ui.widgets.data_table import DataTable

    table = DataTable(["IP", "Open ports"])
    table.begin_bulk_update()
    r0 = table.insert_row()
    table.set_cell(r0, 0, "10.0.0.1", user_data="10.0.0.1")
    table.set_cell(r0, 1, "22,80,8080")
    r1 = table.insert_row()
    table.set_cell(r1, 0, "10.0.0.2", user_data="10.0.0.2")
    table.set_cell(r1, 1, "443")
    table.end_bulk_update()
    return table


def test_port_list_text_survives_sort(qapp) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtCore import Qt

    table = _two_row_table()
    table.table.sortItems(1, Qt.SortOrder.AscendingOrder)
    texts = [table.table.item(row, 1).text() for row in range(table.table.rowCount())]
    # Display text is never rewritten into a concatenated integer.
    assert "22,80,8080" in texts
    assert "443" in texts
    # Ascending by leading port: 22 < 443.
    assert texts[0] == "22,80,8080"
    assert texts[1] == "443"


def test_cell_tooltip_shows_full_value(qapp) -> None:  # type: ignore[no-untyped-def]
    table = _two_row_table()
    assert table.table.item(0, 0).toolTip() == "10.0.0.1"


def test_min_column_widths_enforced_after_resize(qapp) -> None:  # type: ignore[no-untyped-def]
    from packetforge.ui.widgets.data_table import DataTable

    table = DataTable(["IP", "X"], min_column_widths={0: 140})
    row = table.insert_row()
    table.set_cell(row, 0, "192.168.4.100", user_data="192.168.4.100")
    table.set_cell(row, 1, "y")
    table.resize_columns_to_contents()
    assert table.table.columnWidth(0) >= 140
