"""Smart attack orchestration — sequential on single interface."""

from __future__ import annotations

from contextlib import nullcontext
from typing import Type

from .attacks.base import Attack, AttackResult
from .attacks.handshake import HandshakeAttack
from .attacks.pmkid import PMKIDAttack
from .attacks.wep import WEPAttack
from .attacks.wps import WPSPinAttack, WPSPixieAttack
from .models import EncryptionType
from .tools.transition import strategy_summary
from .config import WifluxConfig
from .display import print_crack, print_error, supports_live
from .models import AccessPoint
from .progress import ProgressTracker, get_tracker
from .results import ResultStore

class Orchestrator:
    """Runs attacks in optimal order on a single radio."""

    ATTACK_ORDER: list[Type[Attack]] = [
        WEPAttack,
        WPSPixieAttack,
        WPSPinAttack,
        PMKIDAttack,
        HandshakeAttack,
    ]

    def __init__(self, cfg: WifluxConfig, store: ResultStore, tracker: ProgressTracker | None = None):
        self.cfg = cfg
        self.store = store
        self.tracker = tracker or get_tracker()

    def attack_all(self, targets: list[AccessPoint]) -> int:
        cracked = 0
        live_ctx = (
            self.tracker.live(refresh=4)
            if not self.cfg.output.quiet
            and not self.cfg.output.json_output
            and supports_live()
            else nullcontext()
        )
        self.tracker.enable_skip_controls()
        try:
            with live_ctx:
                for i, ap in enumerate(targets, 1):
                    self.tracker.begin_attack(i, len(targets), ap)
                    self.tracker.refresh()
                    if self._attack_one(ap):
                        cracked += 1
        finally:
            self.tracker.disable_skip_controls()
        return cracked

    def _attack_one(self, ap: AccessPoint) -> bool:
        if ap.is_enterprise:
            self.tracker.log("[red]Skipping enterprise (802.1X)[/]", tag="attack")
            return False

        attacks = self._build_attack_plan(ap)
        if not attacks:
            self.tracker.log("[red]No applicable attacks[/]", tag="attack")
            return False

        plan_names = [c.name for c in attacks]
        self.tracker.log(f"{' → '.join(plan_names)}", tag="plan")
        if ap.transition_mode and self.cfg.attack.transition_downgrade:
            summary = strategy_summary(ap)
            if summary:
                self.tracker.log(f"[cyan]Transition mode[/] — {summary}", tag="plan")

        # One attack at a time — wireless interfaces can't run airodump + hcxdump together
        for idx, attack_cls in enumerate(attacks):
            attack = attack_cls(self.cfg, ap, self.tracker)
            if idx > 0:
                self.tracker.log(
                    f"[cyan]Starting {attack.name}...[/]",
                    tag="plan",
                )
            attack.status("init", f"Preparing {attack.name}...")
            self.tracker.clear_skip()
            self.tracker.refresh()

            try:
                result = attack.run()
            except KeyboardInterrupt:
                raise
            except Exception as e:
                self.tracker.log(f"[red]error: {e}[/]", tag=attack.name)
                result = AttackResult(False, message=str(e))

            if result.skipped:
                self.tracker.log(
                    f"[yellow]Skipped {attack.name} — trying next attack[/]",
                    tag="plan",
                )
            elif result.message:
                style = "green" if result.success and result.crack else "yellow"
                from .display import safe_markup
                self.tracker.log(
                    f"[{style}]{safe_markup(result.message)}[/]",
                    tag=attack.name,
                )

            if result.success and result.crack:
                self.store.save_crack(result.crack)
                self.tracker.clear_attack(attack.name)
                print_crack(result.crack)
                return True

            self.tracker.clear_attack(attack.name)
            self.tracker.refresh()

        return False

    def _build_attack_plan(self, ap: AccessPoint) -> list[Type[Attack]]:
        if ap.encryption == EncryptionType.WEP:
            order = [WEPAttack]
        elif self.cfg.attack.pmkid_only:
            order = [PMKIDAttack]
        elif self.cfg.attack.wps and not self.cfg.attack.pmkid and not self.cfg.attack.handshake:
            order = [WPSPixieAttack, WPSPinAttack]
        else:
            order = self.ATTACK_ORDER
        plan = []
        for cls in order:
            instance = cls(self.cfg, ap, self.tracker)
            if instance.can_attack():
                plan.append(cls)
        return plan

