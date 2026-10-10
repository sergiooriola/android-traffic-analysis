"""Figures of each case, drawn from the tables in ``metrics``."""

from pathlib import Path

import numpy as np
import pandas as pd
from matplotlib.axes import Axes
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.figure import Figure
from matplotlib.ticker import MaxNLocator

from traffic_analysis.cases import Case

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
BAR = "#2a78d6"
# One hue, light to dark: the more transfers, the darker the cell.
SEQUENTIAL = LinearSegmentedColormap.from_list("blues", ["#cde2fb", "#3987e5", "#0d366b"])

SUMMARY_PANELS = (
    ("pii_transfers", "PII transfers"),
    ("unique_transfers", "Unique transfers"),
    ("pii_types", "PII types"),
    ("domains", "Receiving domains"),
)
MAX_APP_LABEL = 34


def _figure(width: float, height: float, title: str) -> Figure:
    figure = Figure(figsize=(width, height), layout="constrained", facecolor=SURFACE)
    figure.suptitle(title, color=INK, fontsize=12, fontweight="bold", x=0.01, ha="left")
    return figure


def _style(ax: Axes, value_axis: str | None) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
    ax.tick_params(colors=MUTED, labelcolor=INK_SECONDARY, labelsize=9, length=0)
    if value_axis:
        # Every value is a count, so the axis only shows whole numbers.
        axis = ax.yaxis if value_axis == "y" else ax.xaxis
        axis.set_major_locator(MaxNLocator(integer=True))
        ax.grid(axis=value_axis, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)


def _save(figure: Figure, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=160, facecolor=SURFACE)
    return path


def _pii_label(pii_type: str) -> str:
    return pii_type.replace("_", " ")


def _app_label(app: str) -> str:
    return app if len(app) <= MAX_APP_LABEL else app[: MAX_APP_LABEL - 1] + "…"


def plot_summary(table: pd.DataFrame, case: Case, path: Path) -> Path:
    """One panel per headline count, one bar per group."""
    figure = _figure(11, 3.4, case.title)
    labels = [label.replace(" ", "\n") for label in table.index]
    for ax, (column, title) in zip(
        figure.subplots(1, len(SUMMARY_PANELS)), SUMMARY_PANELS, strict=True
    ):
        bars = ax.bar(labels, table[column], width=0.5, color=BAR)
        ax.bar_label(bars, color=INK, fontsize=9, padding=2)
        ax.set_title(title, color=INK_SECONDARY, fontsize=10, loc="left")
        ax.margins(y=0.15)
        _style(ax, "y")
    return _save(figure, path)


def plot_pii_types(table: pd.DataFrame, case: Case, path: Path) -> Path:
    """One panel per group, one horizontal bar per PII type, on a shared scale."""
    figure = _figure(1.8 + 3.1 * table.shape[1], 0.6 + 0.36 * len(table), case.title)
    axes = np.atleast_1d(figure.subplots(1, table.shape[1], sharex=True, sharey=True))
    labels = [_pii_label(pii_type) for pii_type in table.index]
    for ax, group in zip(axes, table.columns, strict=True):
        bars = ax.barh(labels, table[group], height=0.6, color=BAR)
        ax.bar_label(bars, color=INK, fontsize=9, padding=3)
        ax.set_title(group, color=INK_SECONDARY, fontsize=10, loc="left")
        ax.set_xlabel("Transfers", color=INK_SECONDARY, fontsize=9)
        ax.margins(x=0.15)
        _style(ax, "x")
    axes[0].invert_yaxis()
    return _save(figure, path)


def plot_pii_types_by_app(tables: dict[str, pd.DataFrame], case: Case, path: Path) -> Path:
    """One heatmap per group: apps in rows, PII types in columns, transfers in cells."""
    first = next(iter(tables.values()))
    apps, pii_types = list(first.index), list(first.columns)
    peak = max(int(table.to_numpy().max()) for table in tables.values()) or 1

    width = 3.2 + 0.62 * len(pii_types) * len(tables)
    figure = _figure(width, 1.8 + 0.27 * len(apps), case.title)
    axes = np.atleast_1d(figure.subplots(1, len(tables), sharey=True))
    for ax, (group, table) in zip(axes, tables.items(), strict=True):
        values = table.to_numpy()
        image = ax.imshow(
            np.ma.masked_equal(values, 0), cmap=SEQUENTIAL, vmin=0, vmax=peak, aspect="auto"
        )
        for row, col in zip(*np.nonzero(values), strict=True):
            value = values[row, col]
            ax.text(
                col,
                row,
                str(value),
                ha="center",
                va="center",
                fontsize=8,
                color=SURFACE if value > 0.45 * peak else INK,
            )
        ax.set_title(group, color=INK_SECONDARY, fontsize=10, loc="left")
        ax.set_xticks(range(len(pii_types)), [_pii_label(pii_type) for pii_type in pii_types])
        ax.set_yticks(range(len(apps)), [_app_label(app) for app in apps])
        ax.tick_params(axis="x", rotation=45)
        for tick in ax.get_xticklabels():
            tick.set_horizontalalignment("right")
        # Hairlines between cells keep the empty ones readable as a grid.
        ax.set_xticks(np.arange(-0.5, len(pii_types)), minor=True)
        ax.set_yticks(np.arange(-0.5, len(apps)), minor=True)
        ax.grid(which="minor", color=GRID, linewidth=0.6)
        ax.tick_params(which="minor", length=0)
        _style(ax, None)
    colorbar = figure.colorbar(image, ax=list(axes), shrink=0.5, pad=0.02)
    colorbar.set_label("Transfers", color=INK_SECONDARY, fontsize=9)
    colorbar.ax.tick_params(colors=MUTED, labelcolor=INK_SECONDARY, labelsize=8, length=0)
    colorbar.outline.set_visible(False)
    return _save(figure, path)
