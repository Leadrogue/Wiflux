"""Wi-Fi band helpers — 2.4 / 5 / 6 GHz channel mapping and tool arguments."""

from __future__ import annotations

# 6 GHz 20 MHz primary channels (IEEE 802.11ax U-NII-5 through U-NII-8).
SIX_GHZ_CHANNELS: tuple[int, ...] = tuple(range(1, 234, 4))


def two_ghz_mhz(channel: int) -> int:
    """Center frequency in MHz for a 2.4 GHz channel number."""
    return 2412 + 5 * (channel - 1)


def six_ghz_mhz(channel: int) -> int:
    """Center frequency in MHz for a 6 GHz channel number."""
    return 5950 + 5 * channel


# Common 5 GHz 20 MHz channel numbers (UNII-1/2/2e/3). Used to disambiguate
# from 6 GHz PSC indices that share some integers.
_FIVE_GHZ_COMMON: frozenset[int] = frozenset({
    7, 8, 9, 11, 12, 16, 32, 34, 36, 38, 40, 42, 44, 46, 48,
    52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
})
_SIX_GHZ_SET: frozenset[int] = frozenset(SIX_GHZ_CHANNELS)


def channel_implies_6ghz(channel: int) -> bool:
    """True when *channel* cannot be 2.4 or 5 GHz (only exists on 6 GHz)."""
    if (15 <= channel <= 35) or channel >= 178:
        return True
    # 6 GHz PSC (1,5,9,...,233) that are not classic 5 GHz channels (e.g. 37).
    if channel in _SIX_GHZ_SET and channel not in _FIVE_GHZ_COMMON and channel > 14:
        return True
    return False


def infer_band(
    channel: int,
    *,
    hint: str = "",
    scan_2ghz: bool = True,
    scan_5ghz: bool = False,
    scan_6ghz: bool = False,
) -> str:
    """Return ``'2'``, ``'5'``, or ``'6'`` for a channel number."""
    if hint in ("2", "5", "6"):
        return hint
    if scan_6ghz and not scan_5ghz and not scan_2ghz:
        return "6"
    if scan_6ghz and not scan_5ghz and channel <= 14:
        return "6"
    if channel_implies_6ghz(channel):
        return "6"
    if channel <= 14:
        return "2"
    if scan_6ghz and channel in _SIX_GHZ_SET and channel not in _FIVE_GHZ_COMMON:
        return "6"
    if channel <= 177:
        return "5"
    if scan_6ghz:
        return "6"
    return "5"


def band_label(band: str) -> str:
    labels = {"2": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}
    return labels.get(band, "unknown band")


def is_high_band(band: str) -> bool:
    return band in ("5", "6")


def hcx_band_suffix(band: str) -> str:
    """hcxdumptool channel suffix: a=2.4, b=5, c=6 GHz."""
    return {"2": "a", "5": "b", "6": "c"}.get(band, "a")


def hcx_channel(channel: int, band: str | None = None, **infer_kw) -> str:
    """Format channel for hcxdumptool (e.g. ``37c`` for 6 GHz ch 37)."""
    resolved = band or infer_band(channel, **infer_kw)
    return f"{channel}{hcx_band_suffix(resolved)}"


def _normalize_channel_token(part: str) -> str:
    """Strip optional ``ch`` prefix (e.g. ``ch36`` → ``36``)."""
    p = (part or "").strip().lower()
    if p.startswith("ch"):
        p = p[2:].strip()
    return p


def parse_channel_spec(channels: str) -> list[int]:
    """Parse ``1,6,11``, ``ch1,ch6``, ``36-48``, or ``ch36-ch48`` style lists."""
    out: list[int] = []
    for part in (channels or "").split(","):
        part = _normalize_channel_token(part)
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start_s = _normalize_channel_token(start_s)
            end_s = _normalize_channel_token(end_s)
            if start_s.isdigit() and end_s.isdigit():
                lo, hi = int(start_s), int(end_s)
                if lo <= hi:
                    out.extend(range(lo, hi + 1))
                else:
                    out.extend(range(hi, lo + 1))
            continue
        if part.isdigit():
            out.append(int(part))
    # Dedupe preserving order
    seen: set[int] = set()
    unique: list[int] = []
    for ch in out:
        if ch not in seen:
            seen.add(ch)
            unique.append(ch)
    return unique


def five_ghz_mhz(channel: int) -> int:
    """Center frequency in MHz for a 5 GHz channel number."""
    return 5000 + 5 * channel


def six_ghz_hop_mhz(channels: str | list[int] | None = None) -> list[int]:
    """MHz center frequencies for airodump-ng ``-C`` 6 GHz hopping."""
    if isinstance(channels, str):
        nums = parse_channel_spec(channels)
        if nums:
            return [six_ghz_mhz(ch) for ch in nums]
    elif isinstance(channels, list) and channels:
        return [six_ghz_mhz(ch) for ch in channels]
    return [six_ghz_mhz(ch) for ch in SIX_GHZ_CHANNELS]


def two_ghz_hop_mhz() -> list[int]:
    return [two_ghz_mhz(ch) for ch in range(1, 15)]


def five_ghz_hop_mhz(channels: list[int] | None = None) -> list[int]:
    """MHz list for 5 GHz hop (optional subset of channels)."""
    if channels:
        return [five_ghz_mhz(ch) for ch in channels if ch > 14]
    return [five_ghz_mhz(ch) for ch in sorted(_FIVE_GHZ_COMMON)]


def _filter_channels_for_bands(
    channels: list[int],
    *,
    scan_2: bool,
    scan_5: bool,
    scan_6: bool,
) -> list[tuple[int, str]]:
    """Return (channel, band) pairs that match the enabled scan bands."""
    out: list[tuple[int, str]] = []
    for ch in channels:
        b = infer_band(ch, scan_2ghz=scan_2, scan_5ghz=scan_5, scan_6ghz=scan_6)
        if b == "2" and scan_2:
            out.append((ch, b))
        elif b == "5" and scan_5:
            out.append((ch, b))
        elif b == "6" and scan_6:
            out.append((ch, b))
    return out


def airodump_band_args(
    cfg,
    *,
    channel: int | None = None,
    band: str | None = None,
) -> list[str]:
    """Build airodump-ng band / frequency / channel-list arguments."""
    args: list[str] = []
    scan_2 = bool(cfg.scan.band_2ghz)
    scan_5 = bool(cfg.scan.band_5ghz)
    scan_6 = bool(cfg.scan.band_6ghz)
    channel_list = parse_channel_spec(cfg.scan.channels) if cfg.scan.channels else []

    # Promote a single-entry channel list to a fixed-channel lock.
    if channel is None and len(channel_list) == 1:
        channel = channel_list[0]

    if channel:
        resolved = band or infer_band(
            channel,
            scan_2ghz=scan_2,
            scan_5ghz=scan_5,
            scan_6ghz=scan_6,
        )
        if resolved == "6":
            args.extend(["-C", str(six_ghz_mhz(channel))])
        else:
            args.extend(["-c", str(channel)])
            if resolved == "5":
                args.extend(["--band", "a"])
        return args

    # Explicit multi-channel list
    if channel_list:
        tagged = _filter_channels_for_bands(
            channel_list, scan_2=scan_2, scan_5=scan_5, scan_6=scan_6,
        )
        if not tagged and channel_list:
            # User listed channels but band filters excluded all — use list as-is.
            tagged = [
                (ch, infer_band(ch, scan_2ghz=True, scan_5ghz=True, scan_6ghz=True))
                for ch in channel_list
            ]
        has_6 = any(b == "6" for _, b in tagged)
        has_5 = any(b == "5" for _, b in tagged)
        has_2 = any(b == "2" for _, b in tagged)
        if has_6:
            # Unified frequency hop (airodump -C) when 6 GHz is involved.
            hop: list[int] = []
            for ch, b in tagged:
                if b == "6":
                    hop.append(six_ghz_mhz(ch))
                elif b == "5":
                    hop.append(five_ghz_mhz(ch))
                else:
                    hop.append(two_ghz_mhz(ch))
            if hop:
                args.extend(["-C", ",".join(str(f) for f in hop)])
            return args
        # 2.4 / 5 only — native channel list
        chans = [str(ch) for ch, _ in tagged]
        if chans:
            args.extend(["-c", ",".join(chans)])
        if has_5 and has_2:
            args.extend(["--band", "abg"])
        elif has_5:
            args.extend(["--band", "a"])
        return args

    # Band-wide hop (no -c list)
    if scan_6:
        hop = []
        if scan_2:
            hop.extend(two_ghz_hop_mhz())
        if scan_5:
            hop.extend(five_ghz_hop_mhz())
        hop.extend(six_ghz_hop_mhz(None))
        args.extend(["-C", ",".join(str(f) for f in hop)])
        return args

    if scan_5 and scan_2:
        args.extend(["--band", "abg"])
    elif scan_5:
        args.extend(["--band", "a"])
    # 2.4-only: airodump default hop
    return args


def set_channel_cmd(iface: str, channel: int, band: str) -> list[list[str]]:
    """Return ordered ``iw`` command attempts for tuning *iface* to *channel*."""
    if band == "6":
        freq = six_ghz_mhz(channel)
        return [
            ["iw", "dev", iface, "set", "channel", str(channel), "band", "6GHz"],
            ["iw", "dev", iface, "set", "freq", str(freq), "MHz"],
            ["iw", "dev", iface, "set", "freq", str(freq)],
        ]
    if band == "5":
        cmds: list[list[str]] = []
        for width in ("80MHz", "40MHz", "20MHz"):
            cmds.append(["iw", "dev", iface, "set", "channel", str(channel), width])
        cmds.append(["iw", "dev", iface, "set", "channel", str(channel)])
        return cmds
    return [["iw", "dev", iface, "set", "channel", str(channel)]]


def tag_band_for_ap(channel: int, cfg) -> str:
    """Band tag to store on scanned access points."""
    return infer_band(
        channel,
        scan_2ghz=bool(cfg.scan.band_2ghz),
        scan_5ghz=bool(cfg.scan.band_5ghz),
        scan_6ghz=bool(cfg.scan.band_6ghz),
    )