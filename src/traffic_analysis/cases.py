"""The three case studies, each a comparison between groups of captures."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Group:
    """One side of a comparison: a capture campaign observed in one phase."""

    label: str
    campaign: str
    phase: str


@dataclass(frozen=True)
class Case:
    key: str
    title: str
    factor: str
    groups: tuple[Group, ...]


CASES = (
    Case(
        key="case1",
        title="Case 1: interaction tool",
        factor="Interaction tool",
        groups=(
            Group("Exerciser Monkey", "case1_logging", "dynamic"),
            Group("Appium", "case1_loggingAppium", "dynamic"),
            Group("Manual", "case1_loggingManual", "dynamic"),
        ),
    ),
    Case(
        key="case2",
        title="Case 2: authentication",
        factor="Session",
        groups=(
            Group("Not authenticated", "case2_loggingAuthMonkey", "dynamic"),
            Group("Authenticated", "case2_loggingAuthManual", "dynamic"),
        ),
    ),
    Case(
        key="case3",
        title="Case 3: dynamic vs idle",
        factor="Phase",
        groups=(
            Group("Dynamic", "case3_loggingDynVsIdle", "dynamic"),
            Group("Idle", "case3_loggingDynVsIdle", "idle"),
        ),
    ),
)

CASES_BY_KEY = {case.key: case for case in CASES}
