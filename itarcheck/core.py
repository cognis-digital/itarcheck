"""Core scanning engine for ITARCHECK.

Standard library only. The engine matches text against a curated rule set of
ITAR/EAR control indicators, classifies severity, and attributes each match to
a USML category and/or an EAR control reason where applicable.

The rule set is illustrative and intended as a CI screening aid — it is NOT a
legal determination. All findings should be reviewed by an empowered official.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Iterable, Iterator


class Severity(str, Enum):
    """Confidence/risk tier for a flagged term."""

    HIGH = "high"      # strong USML / named-defense-article indicator
    MEDIUM = "medium"  # dual-use or EAR-controlled indicator
    LOW = "low"        # contextual / advisory indicator

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


# United States Munitions List categories (22 CFR 121.1), abbreviated titles.
USML_CATEGORIES: dict[str, str] = {
    "I": "Firearms and Related Articles",
    "II": "Guns and Armament",
    "III": "Ammunition and Ordnance",
    "IV": "Launch Vehicles, Missiles, Rockets, Torpedoes, Bombs, Mines",
    "V": "Explosives and Energetic Materials, Propellants",
    "VI": "Surface Vessels of War and Special Naval Equipment",
    "VII": "Ground Vehicles",
    "VIII": "Aircraft and Related Articles",
    "IX": "Military Training Equipment",
    "X": "Personal Protective Equipment",
    "XI": "Military Electronics",
    "XII": "Fire Control, Laser, Imaging, and Guidance Equipment",
    "XIII": "Materials and Miscellaneous Articles",
    "XIV": "Toxicological Agents and Equipment",
    "XV": "Spacecraft and Related Articles",
    "XVI": "Nuclear Weapons Related Articles",
    "XVII": "Classified Articles and Technical Data",
    "XVIII": "Directed Energy Weapons",
    "XIX": "Gas Turbine Engines and Associated Equipment",
    "XX": "Submersible Vessels and Related Articles",
    "XXI": "Articles Not Otherwise Enumerated",
}


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    pattern: str                 # regex source, matched case-insensitively
    severity: Severity
    regime: str                  # "ITAR" | "EAR" | "ADVISORY"
    usml: str | None             # USML category key, if applicable
    ear_reason: str | None       # EAR control reason / ECCN hint, if applicable
    description: str

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE)


# Curated rule set. Word boundaries (\b) keep matches precise; alternations
# group synonyms. Kept deliberately conservative to limit false positives.
_RULES: tuple[Rule, ...] = (
    # --- ITAR / USML high-confidence indicators -----------------------------
    Rule("ITAR-XII-GUIDANCE", r"\b(guidance\s+(?:system|unit|computer)|seeker\s+head|terminal\s+guidance|inertial\s+(?:navigation|measurement)\s+unit|\bIMU\b)\b",
         Severity.HIGH, "ITAR", "XII", None,
         "Fire-control / guidance equipment terminology (USML Cat XII)."),
    Rule("ITAR-IV-MISSILE", r"\b(guided\s+missile|ballistic\s+missile|warhead|reentry\s+vehicle|MIRV|torpedo|sea\s+mine)\b",
         Severity.HIGH, "ITAR", "IV", None,
         "Missile / ordnance terminology (USML Cat IV)."),
    Rule("ITAR-XV-SPACECRAFT", r"\b(spacecraft\s+bus|satellite\s+payload|radiation[-\s]?hardened|rad[-\s]?hard|star\s+tracker|space[-\s]?qualified)\b",
         Severity.HIGH, "ITAR", "XV", None,
         "Spacecraft / space-qualified hardware terminology (USML Cat XV)."),
    Rule("ITAR-XVIII-DEW", r"\b(directed\s+energy\s+weapon|high[-\s]?energy\s+laser|\bHEL\b|high[-\s]?power\s+microwave|\bHPM\b)\b",
         Severity.HIGH, "ITAR", "XVIII", None,
         "Directed-energy weapon terminology (USML Cat XVIII)."),
    Rule("ITAR-XI-MILELEC", r"\b(electronic\s+(?:warfare|attack)|\bECM\b|\bECCM\b|signals\s+intelligence|\bSIGINT\b|anti[-\s]?jam)\b",
         Severity.HIGH, "ITAR", "XI", None,
         "Military electronics / EW terminology (USML Cat XI)."),
    Rule("ITAR-VIII-AIRCRAFT", r"\b(military\s+aircraft|unmanned\s+(?:aerial|combat)\s+vehicle|\bUCAV\b|fighter\s+jet|attack\s+helicopter)\b",
         Severity.HIGH, "ITAR", "VIII", None,
         "Military aircraft terminology (USML Cat VIII)."),
    Rule("ITAR-XIV-TOXIC", r"\b(chemical\s+(?:warfare|agent)|nerve\s+agent|biological\s+(?:weapon|agent)|\bVX\b\s+agent)\b",
         Severity.HIGH, "ITAR", "XIV", None,
         "Toxicological agent terminology (USML Cat XIV)."),
    Rule("ITAR-XVI-NUCLEAR", r"\b(nuclear\s+weapon|nuclear\s+warhead|fissile\s+(?:material|core)|weapons[-\s]?grade)\b",
         Severity.HIGH, "ITAR", "XVI", None,
         "Nuclear-weapon-related terminology (USML Cat XVI)."),
    Rule("ITAR-XIX-TURBINE", r"\b(military\s+gas\s+turbine|afterburner\s+control|\bFADEC\b)\b",
         Severity.HIGH, "ITAR", "XIX", None,
         "Military gas-turbine engine terminology (USML Cat XIX)."),
    Rule("ITAR-TECHDATA", r"\b(technical\s+data\s+package|\bTDP\b|defense\s+article|defense\s+service|ITAR[-\s]?controlled)\b",
         Severity.HIGH, "ITAR", "XVII", None,
         "Explicit defense-article / technical-data marking (ITAR 120.10/120.6)."),

    # --- EAR / CCL dual-use indicators --------------------------------------
    Rule("EAR-CRYPTO", r"\b(AES[-\s]?256|RSA[-\s]?(?:2048|4096)|elliptic[-\s]?curve|key\s+length|symmetric\s+cipher|encryption\s+module)\b",
         Severity.MEDIUM, "EAR", None, "5A002/5D002 (information security)",
         "Cryptographic functionality may be EAR Cat 5 Part 2 controlled."),
    Rule("EAR-SEMICONDUCTOR", r"\b(GaN|gallium\s+nitride|GaAs|MMIC|monolithic\s+microwave|FPGA\s+bitstream|ASIC\s+netlist)\b",
         Severity.MEDIUM, "EAR", None, "3A001/3A090 (electronics)",
         "Advanced semiconductor terminology may be EAR Cat 3 controlled."),
    Rule("EAR-SENSORS", r"\b(focal\s+plane\s+array|infrared\s+detector|read[-\s]?out\s+integrated\s+circuit|\bROIC\b|night\s+vision)\b",
         Severity.MEDIUM, "EAR", None, "6A002/6A003 (sensors and lasers)",
         "Imaging/sensor terminology may be EAR Cat 6 controlled."),
    Rule("EAR-PROPULSION", r"\b(solid\s+rocket\s+motor|liquid\s+propellant|hypersonic|scramjet|composite\s+overwrap)\b",
         Severity.MEDIUM, "EAR", None, "9A (aerospace and propulsion) / MTCR",
         "Propulsion terminology may be EAR Cat 9 / MTCR controlled."),
    Rule("EAR-NAVIGATION", r"\b(GNSS\s+anti[-\s]?spoof|military\s+GPS|M[-\s]?code|accelerometer\s+bias|gyro\s+drift)\b",
         Severity.MEDIUM, "EAR", None, "7A (navigation and avionics)",
         "Navigation/avionics terminology may be EAR Cat 7 controlled."),

    # --- Advisory / contextual ----------------------------------------------
    Rule("ADV-COUNTRY", r"\b(export\s+to|ship\s+to|destined\s+for)\s+(China|Russia|Iran|North\s+Korea|Cuba|Syria|Venezuela)\b",
         Severity.HIGH, "ADVISORY", None, "OFAC/EAR embargoed or restricted destination",
         "Reference to a sanctioned/embargoed destination (review EAR 746 / OFAC)."),
    Rule("ADV-MILSPEC", r"\b(MIL[-\s]?STD[-\s]?\d+|MIL[-\s]?SPEC|MIL[-\s]?PRF[-\s]?\d+|DO[-\s]?178[CB]?)\b",
         Severity.LOW, "ADVISORY", None, None,
         "Military specification reference; review for controlled context."),
    Rule("ADV-CLASSIFICATION", r"\b(SECRET//NOFORN|TOP\s+SECRET|CUI//SP[-\s]?CTI|NOFORN|classified)\b",
         Severity.MEDIUM, "ADVISORY", None, None,
         "Classification / dissemination marking present; handle accordingly."),
)

_COMPILED: tuple[tuple[Rule, re.Pattern[str]], ...] = tuple(
    (rule, rule.compile()) for rule in _RULES
)

DEFAULT_TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".txt", ".md", ".rst", ".py", ".c", ".h", ".cpp", ".hpp", ".cc",
    ".java", ".go", ".rs", ".js", ".ts", ".json", ".yaml", ".yml",
    ".cfg", ".ini", ".csv", ".xml", ".html", ".sh", ".tex", "",
})


@dataclass(frozen=True)
class Finding:
    """A single flagged occurrence."""

    rule_id: str
    severity: Severity
    regime: str
    path: str
    line: int
    column: int
    match: str
    usml_category: str | None
    usml_title: str | None
    ear_reason: str | None
    description: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    """Aggregate result of a scan."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0

    @property
    def counts(self) -> dict[str, int]:
        out = {"high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }


def scan_text(text: str, path: str = "<text>") -> list[Finding]:
    """Scan a block of text and return findings (one per match)."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in _COMPILED:
            for m in pattern.finditer(line):
                usml_title = (
                    USML_CATEGORIES.get(rule.usml) if rule.usml else None
                )
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        regime=rule.regime,
                        path=path,
                        line=lineno,
                        column=m.start() + 1,
                        match=m.group(0).strip(),
                        usml_category=rule.usml,
                        usml_title=usml_title,
                        ear_reason=rule.ear_reason,
                        description=rule.description,
                    )
                )
    return findings


def _iter_files(
    root: Path, extensions: frozenset[str]
) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in extensions:
            yield p


def scan_path(
    target: str | Path,
    extensions: Iterable[str] | None = None,
    max_bytes: int = 5_000_000,
) -> ScanResult:
    """Scan a file or directory tree.

    Binary / oversized / unreadable files are counted as skipped rather than
    raising, so the tool degrades gracefully in CI.
    """
    root = Path(target)
    if not root.exists():
        raise FileNotFoundError(f"path does not exist: {root}")

    exts = frozenset(e.lower() for e in extensions) if extensions else DEFAULT_TEXT_EXTENSIONS
    result = ScanResult()

    for path in _iter_files(root, exts):
        try:
            if path.stat().st_size > max_bytes:
                result.files_skipped += 1
                continue
            raw = path.read_bytes()
            if b"\x00" in raw[:4096]:  # crude binary sniff
                result.files_skipped += 1
                continue
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(text, str(path)))

    result.findings.sort(
        key=lambda f: (-f.severity.rank, f.path, f.line, f.column)
    )
    return result


def summarize(result: ScanResult) -> str:
    """Human-readable one-line summary."""
    c = result.counts
    return (
        f"{len(result.findings)} finding(s) "
        f"[high={c['high']} medium={c['medium']} low={c['low']}] "
        f"across {result.files_scanned} file(s); {result.files_skipped} skipped"
    )


def exceeds_threshold(result: ScanResult, fail_on: Severity) -> bool:
    """True if any finding meets/exceeds the fail-on severity tier."""
    return any(f.severity.rank >= fail_on.rank for f in result.findings)
