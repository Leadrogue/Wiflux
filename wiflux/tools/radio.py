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


def channel_implies_6ghz(channel: int) -> bool:
    """True when *channel* cannot be 2.4 or 5 GHz (only exists on 6 GHz)."""
    return (15 <= channel <= 35) or channel >= 178


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


def parse_channel_spec(channels: str) -> list[int]:
    """Parse ``1,6,11`` or ``36-48`` style channel lists."""
    out: list[int] = []
    for part in channels.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            if start_s.strip().isdigit() and end_s.strip().isdigit():
                out.extend(range(int(start_s), int(end_s) + 1))
            continue
        if part.isdigit():
            out.append(int(part))
    return out


def six_ghz_hop_mhz(channels: str | None = None) -> list[int]:
    """MHz center frequencies for airodump-ng ``-C`` 6 GHz hopping."""
    if channels:
        nums = parse_channel_spec(channels)
        if nums:
            return [six_ghz_mhz(ch) for ch in nums]
    return [six_ghz_mhz(ch) for ch in SIX_GHZ_CHANNELS]


def two_ghz_hop_mhz() -> list[int]:
    return [two_ghz_mhz(ch) for ch in range(1, 15)]


def airodump_band_args(
    cfg,
    *,
    channel: int | None = None,
    band: str | None = None,
) -> list[str]:
    """Build airodump-ng band / frequency arguments."""
    args: list[str] = []
    scan_2 = cfg.scan.band_2ghz
    scan_5 = cfg.scan.band_5ghz
    scan_6 = cfg.scan.band_6ghz

    if channel:
        resolved = band or infer_band(
            channel,
            scan_2ghz=scan_2,
            scan_5ghz=scan_5,
            scan_6ghz=scan_6,
        )
        args.extend(["-c", str(channel)])
        if resolved == "5":
            args.extend(["--band", "a"])
        elif resolved == "6":
            args.extend(["-C", str(six_ghz_mhz(channel))])
        return args

    hop_mhz: list[int] = []
    if scan_6:
        hop_mhz.extend(six_ghz_hop_mhz(cfg.scan.channels if scan_6 else None))
    if scan_6 and scan_2 and not scan_5:
        hop_mhz = two_ghz_hop_mhz() + hop_mhz

    if scan_5 and scan_2:
        args.extend(["--band", "abg"])
    elif scan_5:
        args.extend(["--band", "a"])

    if hop_mhz:
        args.extend(["-C", ",".join(str(f) for f in hop_mhz)])
    elif scan_6 and not scan_2 and not scan_5:
        args.extend(["-C", ",".join(str(f) for f in six_ghz_hop_mhz(cfg.scan.channels))])

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
    if cfg.scan.band_6ghz and not cfg.scan.band_5ghz and not cfg.scan.band_2ghz:
        return "6"
    if cfg.scan.band_6ghz and channel_implies_6ghz(channel):
        return "6"
    if cfg.scan.band_6ghz and cfg.scan.channels and not cfg.scan.band_5ghz:
        return "6"
    if channel <= 14:
        return "2"
    if channel <= 177:
        return "5"
    return "6" if cfg.scan.band_6ghz else "5"