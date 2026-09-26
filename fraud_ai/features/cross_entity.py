"""Cross-entity features: sharing of devices and networks between accounts.

Sharing is descriptive. Carrier NAT, offices, schools, hotels and households legitimately
share networks (and families share devices); these features are never verdicts.
"""

from __future__ import annotations

from fraud_ai.features._common import NA, NOT_OBSERVED
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter


def compute(h: History, w: FeatureWriter) -> None:
    ctx = h.ctx
    if ctx.device_id is None:
        w.miss_all(("accounts_per_device", "shared_device_flag"), NOT_OBSERVED)
    else:
        others = h.device.other_accounts
        w.put("accounts_per_device", others)
        w.put("shared_device_flag", others >= 1)
    if ctx.network is None:
        w.miss_all(("accounts_per_network", "shared_network_flag"), NOT_OBSERVED)
    else:
        others = h.network.other_accounts
        w.put("accounts_per_network", others)
        w.put("shared_network_flag", others >= 1)
    per_account = (
        "addresses_per_account",
        "devices_per_account",
        "payment_methods_per_account",
        "networks_per_account",
    )
    if ctx.user_id is None:
        w.miss_all(per_account, NA)
        return
    w.put("addresses_per_account", h.user_addresses.total)
    w.put("devices_per_account", h.user_devices.total)
    w.put("payment_methods_per_account", h.user_payment_methods.total)
    w.put("networks_per_account", h.networks_per_account)
