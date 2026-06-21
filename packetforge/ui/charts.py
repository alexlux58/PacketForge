"""Reusable PyQtGraph chart builders for the observability layer.

Every helper converts a chart-ready model (built off the GUI thread) into a
lightweight widget. Keeping this isolated means the same charts can be embedded
as mini-visuals inside other tabs without duplicating PyQtGraph boilerplate.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

import numpy as np
import pyqtgraph as pg
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from packetforge.models.observability import ChartSeries, HeatmapMatrix

pg.setConfigOption("background", "#111418")
pg.setConfigOption("foreground", "#aeb8c3")

_PALETTE = ["#3da5ff", "#36c275", "#f5a623", "#b48cff", "#ff6b6b", "#22b8cf", "#e879f9"]


def _category_axis(categories: Sequence[str]) -> pg.AxisItem:
    axis = pg.AxisItem(orientation="bottom")
    ticks = [(float(i), str(label)) for i, label in enumerate(categories)]
    axis.setTicks([ticks])
    return axis


def _empty(message: str) -> QWidget:
    holder = QWidget()
    layout = QVBoxLayout(holder)
    layout.setContentsMargins(8, 8, 8, 8)
    label = QLabel(message)
    label.setObjectName("Muted")
    label.setWordWrap(True)
    layout.addWidget(label)
    return holder


def _add_legend(plot: pg.PlotWidget) -> pg.LegendItem:
    """Add a legend with an opaque background so keys stay readable over bars."""
    legend = plot.addLegend(offset=(-10, 10))
    legend.setBrush(pg.mkBrush("#1b2128"))
    legend.setPen(pg.mkPen("#3b4654"))
    legend.setLabelTextColor("#e7edf3")
    return legend


def bar_chart(series: ChartSeries, *, height: int | None = None) -> QWidget:
    if series.is_empty:
        return _empty(f"No data for: {series.name}")
    axis_items = {"bottom": _category_axis(series.categories)} if series.categories else {}
    plot = pg.PlotWidget(axisItems=axis_items)
    plot.setTitle(series.name)
    if series.y_label:
        plot.setLabel("left", series.y_label, units=series.unit or None)
    x = series.x or [float(i) for i in range(len(series.y))]
    color = series.color or _PALETTE[0]
    bar = pg.BarGraphItem(x=x, height=series.y, width=0.6, brush=color, pen=color)
    plot.addItem(bar)
    plot.showGrid(x=False, y=True, alpha=0.2)
    if series.categories:
        plot.getAxis("bottom").setStyle(tickTextOffset=6)
    if height:
        plot.setMinimumHeight(height)
    return cast(QWidget, plot)


def grouped_bar_chart(
    series_list: Sequence[ChartSeries], title: str, *, height: int | None = None
) -> QWidget:
    non_empty = [s for s in series_list if not s.is_empty]
    if not non_empty:
        return _empty(f"No data for: {title}")
    categories = non_empty[0].categories
    axis_items = {"bottom": _category_axis(categories)} if categories else {}
    plot = pg.PlotWidget(axisItems=axis_items)
    plot.setTitle(title)
    _add_legend(plot)
    count = len(non_empty)
    group_width = 0.8
    bar_width = group_width / max(1, count)
    for index, series in enumerate(non_empty):
        offset = -group_width / 2 + bar_width * (index + 0.5)
        x = [float(i) + offset for i in range(len(series.y))]
        color = series.color or _PALETTE[index % len(_PALETTE)]
        bar = pg.BarGraphItem(
            x=x, height=series.y, width=bar_width * 0.9, brush=color, pen=color, name=series.name
        )
        plot.addItem(bar)
    plot.showGrid(x=False, y=True, alpha=0.2)
    if height:
        plot.setMinimumHeight(height)
    return cast(QWidget, plot)


def line_chart(
    series_list: Sequence[ChartSeries],
    title: str,
    *,
    height: int | None = None,
    step: bool = False,
) -> QWidget:
    non_empty = [s for s in series_list if not s.is_empty]
    if not non_empty:
        return _empty(f"No data for: {title}")
    plot = pg.PlotWidget()
    plot.setTitle(title)
    _add_legend(plot)
    first = non_empty[0]
    if first.x_label:
        plot.setLabel("bottom", first.x_label)
    if first.y_label:
        plot.setLabel("left", first.y_label, units=first.unit or None)
    for index, series in enumerate(non_empty):
        color = series.color or _PALETTE[index % len(_PALETTE)]
        x = series.x or [float(i) for i in range(len(series.y))]
        pen = pg.mkPen(color=color, width=2)
        use_step = step or series.kind == "step"
        plot.plot(
            x, series.y, pen=pen, name=series.name,
            stepMode="right" if use_step and len(x) == len(series.y) else None,
        )
    plot.showGrid(x=True, y=True, alpha=0.2)
    if height:
        plot.setMinimumHeight(height)
    return cast(QWidget, plot)


def histogram_chart(series: ChartSeries, *, height: int | None = None) -> QWidget:
    if series.is_empty:
        return _empty(f"No data for: {series.name}")
    plot = pg.PlotWidget()
    plot.setTitle(series.name)
    plot.setLabel("left", series.y_label or "count")
    if series.x_label:
        plot.setLabel("bottom", series.x_label, units=series.unit or None)
    width = (series.x[1] - series.x[0]) * 0.9 if len(series.x) > 1 else 1.0
    bar = pg.BarGraphItem(
        x=series.x, height=series.y, width=width, brush=_PALETTE[3], pen=_PALETTE[3]
    )
    plot.addItem(bar)
    plot.showGrid(x=False, y=True, alpha=0.2)
    if height:
        plot.setMinimumHeight(height)
    return cast(QWidget, plot)


def heatmap_widget(matrix: HeatmapMatrix, *, height: int | None = None) -> QWidget:
    if matrix.is_empty:
        return _empty("No port data yet. Run discovery with TCP/UDP probes.")
    data = np.array(matrix.values, dtype=float)
    glw = pg.GraphicsLayoutWidget()
    plot = glw.addPlot(title=matrix.title)
    image = pg.ImageItem()
    # ImageItem treats the first axis as x; transpose so rows map to the y axis.
    image.setImage(data.T)
    color_map = pg.colormap.get("viridis") if hasattr(pg, "colormap") else None
    if color_map is not None:
        image.setLookupTable(color_map.getLookupTable(0.0, 1.0, 256))
    image.setLevels((0.0, 1.0))
    plot.addItem(image)
    plot.getAxis("bottom").setTicks(
        [[(i + 0.5, label) for i, label in enumerate(matrix.columns)]]
    )
    plot.getAxis("left").setTicks([[(i + 0.5, label) for i, label in enumerate(matrix.rows)]])
    plot.setLabel("bottom", matrix.col_label)
    plot.setLabel("left", matrix.row_label)
    plot.invertY(True)
    plot.setMouseEnabled(x=True, y=True)
    if height:
        glw.setMinimumHeight(height)
    return cast(QWidget, glw)


def sparkline(values: Sequence[float], *, color: str = "#3da5ff") -> QWidget:
    if not values:
        return _empty("no samples")
    plot = pg.PlotWidget()
    plot.setMenuEnabled(False)
    plot.hideAxis("bottom")
    plot.hideButtons()
    plot.plot(list(range(len(values))), list(values), pen=pg.mkPen(color=color, width=2))
    plot.setMaximumHeight(70)
    return cast(QWidget, plot)


def color_for(name: str) -> QColor:
    index = abs(hash(name)) % len(_PALETTE)
    return QColor(_PALETTE[index])
