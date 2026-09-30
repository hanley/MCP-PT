"""NetFlow Exporter on a PT Device. 

Unlike the rest of the advanced features, NetFlow is NOT enforced by CLI: 
the native PT API exposes 'NFExporterManager.createNFExporter(name)' and the 
setters of the exporter, so it is configured per object and can be reread to 
check ('isFullyConfigured()'). 
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class NetflowExporter(BaseModel):
    """A NetFlow exporter: where the device sends the flows."""

    device: str
    name: str
    destination_ip: str = ""
    udp_port: int = 2055
    version: int = 9
    source_port: str = ""            # source interface; empty = PT chooses
    monitors: list[str] = Field(default_factory=list)
