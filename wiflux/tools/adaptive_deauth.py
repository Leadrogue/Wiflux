"""Adaptive deauth timing — tunes burst intensity and listen windows from capture feedback."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .radio import is_high_band


class DeauthOutcome(str, Enum):
    RESPONSIVE = "responsive"
    DEAUTH_SEEN = "deauth_seen"
    SILENT = "silent"
    MIXED = "mixed"


@dataclass(frozen=True)
class DeauthSnapshot:
    eapol: int = 0
    deauth_rx: int = 0
    auth: int = 0
    assoc: int = 0
    reconnect: bool = False

    @classmethod
    def from_stats(cls, stats: dict[str, int | bool] | None) -> DeauthSnapshot:
        if not stats:
            return cls()
        return cls(
            eapol=int(stats.get("eapol", 0) or 0),
            deauth_rx=int(stats.get("deauth_rx", 0) or 0),
            auth=int(stats.get("auth", 0) or 0),
            assoc=int(stats.get("assoc", 0) or 0),
            reconnect=bool(stats.get("reconnect", False)),
        )


@dataclass(frozen=True)
class AdaptiveDeauthParams:
    interval: float
    listen_window: float
    packet_count: int
    passive_first: float
    passive_extension: float = 0.0
    use_band_block: bool = True
    strategy: str = "balanced"
    outcome: str = ""


def classify_outcome(before: DeauthSnapshot, after: DeauthSnapshot) -> DeauthOutcome:
    """Classify how the target reacted between two capture-health snapshots."""
    eapol_gain = after.eapol - before.eapol
    if eapol_gain > 0:
        return DeauthOutcome.RESPONSIVE
    if after.reconnect and not before.reconnect:
        return DeauthOutcome.RESPONSIVE
    if (
        after.auth > before.auth
        or after.assoc > before.assoc
        or after.deauth_rx > before.deauth_rx
    ):
        return DeauthOutcome.DEAUTH_SEEN
    if (
        after.eapol == before.eapol
        and after.deauth_rx == before.deauth_rx
        and after.auth == before.auth
        and after.assoc == before.assoc
        and after.reconnect == before.reconnect
    ):
        return DeauthOutcome.SILENT
    return DeauthOutcome.MIXED


class AdaptiveDeauthEngine:
    """Tune deauth cadence from live capture-health feedback."""

    INTERVAL_MIN = 8.0
    INTERVAL_MAX = 45.0
    LISTEN_MIN = 8.0
    LISTEN_MAX = 32.0
    PACKET_MIN = 2
    PACKET_MAX = 8
    PASSIVE_FIRST_5GHZ = 20.0
    PASSIVE_FIRST_24GHZ = 12.0

    def __init__(
        self,
        *,
        deauth_listen: int = 8,
        deauth_burst: int = 5,
        channel: int = 6,
        band: str = "",
        enabled: bool = True,
    ):
        self.enabled = enabled
        self.channel = channel
        self.band = band or ("5" if channel > 14 else "2")
        self.is_5ghz = self.band == "5"
        self.is_high_band = is_high_band(self.band)

        base_listen = max(12.0, float(deauth_listen))
        self._interval = max(self.INTERVAL_MIN, base_listen)
        self._listen = max(self.LISTEN_MIN, base_listen * 0.75)
        self._packets = max(self.PACKET_MIN, min(self.PACKET_MAX, int(deauth_burst)))
        self._passive_first = (
            self.PASSIVE_FIRST_5GHZ if self.is_high_band else self.PASSIVE_FIRST_24GHZ
        )
        self._passive_extension = 0.0
        self._use_band_block = self.band == "5"

        self.rounds = 0
        self.consecutive_silent = 0
        self.consecutive_responsive = 0
        self.consecutive_deauth_seen = 0
        self.last_outcome = DeauthOutcome.MIXED
        self.strategy = "balanced"
        self.last_reason = ""

    def initial_params(self) -> AdaptiveDeauthParams:
        return AdaptiveDeauthParams(
            interval=self._interval,
            listen_window=self._listen,
            packet_count=self._packets,
            passive_first=self._passive_first,
            passive_extension=0.0,
            use_band_block=self._use_band_block,
            strategy=self.strategy,
        )

    def record_outcome(
        self,
        before: DeauthSnapshot,
        after: DeauthSnapshot,
    ) -> AdaptiveDeauthParams:
        """Update internal tuning from a completed deauth + listen cycle."""
        self.rounds += 1
        if not self.enabled:
            self.last_reason = "adaptive disabled"
            return self.initial_params()

        outcome = classify_outcome(before, after)
        self.last_outcome = outcome
        self._passive_extension = 0.0

        if outcome == DeauthOutcome.RESPONSIVE:
            self.consecutive_silent = 0
            self.consecutive_deauth_seen = 0
            self.consecutive_responsive += 1
            self._interval = max(self.INTERVAL_MIN, self._interval * 0.82)
            self._listen = min(self.LISTEN_MAX, self._listen * 1.28)
            self._packets = max(self.PACKET_MIN, self._packets - 1)
            self.strategy = "responsive"
            self.last_reason = "client reconnect/EAPOL — shorter gap, longer listen"
        elif outcome == DeauthOutcome.DEAUTH_SEEN:
            self.consecutive_silent = 0
            self.consecutive_responsive = 0
            self.consecutive_deauth_seen += 1
            self._interval = min(self.INTERVAL_MAX, self._interval * 1.3)
            self._listen = min(self.LISTEN_MAX, self._listen * 1.12)
            self._packets = max(self.PACKET_MIN, self._packets - 1)
            self.strategy = "gentle"
            self.last_reason = "deauth observed but no handshake — easing bursts"
            if self.consecutive_deauth_seen >= 3:
                self._passive_extension = 6.0
                self._use_band_block = False
                self.last_reason += "; pausing for passive capture"
        elif outcome == DeauthOutcome.SILENT:
            self.consecutive_responsive = 0
            self.consecutive_deauth_seen = 0
            self.consecutive_silent += 1
            if self.consecutive_silent <= 2:
                self._packets = min(self.PACKET_MAX, self._packets + 1)
                self._interval = min(self.INTERVAL_MAX, self._interval * 1.08)
                self.strategy = "probe"
                self.last_reason = "no reaction — probing with slightly stronger burst"
            elif self.consecutive_silent <= 4:
                self._interval = min(self.INTERVAL_MAX, self._interval * 1.22)
                self._packets = max(self.PACKET_MIN, self._packets - 1)
                self._listen = min(self.LISTEN_MAX, self._listen * 1.15)
                self.strategy = "backoff"
                self.last_reason = "still silent — backing off deauth cadence"
            else:
                self._interval = min(self.INTERVAL_MAX, max(self._interval * 1.35, 28.0))
                self._packets = self.PACKET_MIN
                self._listen = min(self.LISTEN_MAX, self._listen * 1.25)
                self._passive_extension = 10.0 if self.is_high_band else 6.0
                self._use_band_block = False
                self.strategy = "passive-heavy"
                self.last_reason = "repeated silence — passive listen, minimal deauth"
        else:
            self.consecutive_responsive = 0
            self.consecutive_silent = max(0, self.consecutive_silent - 1)
            self.consecutive_deauth_seen = 0
            self._interval = min(self.INTERVAL_MAX, self._interval * 1.05)
            self.strategy = "balanced"
            self.last_reason = "mixed signals — holding steady"

        if self.consecutive_responsive >= 2:
            self._listen = min(self.LISTEN_MAX, self._listen + 2.0)
            self.last_reason += "; sustained activity — extending listen"

        return self.next_params()

    def next_params(self) -> AdaptiveDeauthParams:
        return AdaptiveDeauthParams(
            interval=round(self._interval, 1),
            listen_window=round(self._listen, 1),
            packet_count=int(self._packets),
            passive_first=self._passive_first,
            passive_extension=self._passive_extension,
            use_band_block=self._use_band_block,
            strategy=self.strategy,
            outcome=self.last_outcome.value,
        )

    def should_warn_ineffective(self) -> bool:
        return self.rounds >= 2 and self.consecutive_silent >= 2

    def ineffective_warning_detail(self) -> str:
        """Human-readable next step after deauth appears ineffective."""
        hints = {
            "probe": "probing with slightly stronger bursts",
            "backoff": "backing off deauth cadence, longer passive listen",
            "passive-heavy": "mostly passive listen with minimal deauth",
            "gentle": "gentler deauth bursts, longer gaps",
            "responsive": "client activity detected — extending listen windows",
            "balanced": "continuing capture with reduced deauth pressure",
        }
        hint = hints.get(self.strategy, self.strategy)
        parts = [hint]
        if self._passive_extension > 0:
            parts.append(f"passive pause {self._passive_extension:.0f}s")
        if not self._use_band_block and self.is_5ghz:
            parts.append("band-block disabled")
        return "; ".join(parts)