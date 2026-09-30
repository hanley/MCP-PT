"""Fine-tuning model per interface (clock-rate, bandwidth, OSPF/EIGRP knobs)."""

from __future__ import annotations
from pydantic import BaseModel


class InterfaceTuning(BaseModel):
    """Parameters of a specific interface of a router. All optional."""
    router: str
    interface: str
    clock_rate: int | None = None        # only on Serial interfaces (DCE endpoint)
    bandwidth: int | None = None         # kbps
    ospf_cost: int | None = None
    ospf_priority: int | None = None
    ospf_hello_interval: int | None = None
    ospf_dead_interval: int | None = None
    delay: int | None = None             # EIGRP delay (tens of microseconds)

    # OSPF authentication. With 'ospf_md5_key' you use message-digest (recommended); 
    # 'ospf_auth_key' alone is plaintext authentication, which travels readable.
    ospf_auth_key: str | None = None
    ospf_md5_key_id: int | None = None
    ospf_md5_key: str | None = None

    def uses_md5_auth(self) -> bool:
        return self.ospf_md5_key is not None

    def is_serial(self) -> bool:
        return self.interface.lower().startswith("serial")
