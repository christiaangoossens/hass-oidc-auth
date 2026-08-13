

from datetime import datetime
from custom_components.auth_oidc.tools.types import UserDetails
from dataclasses import dataclass
from typing import Dict, Any, Literal


@dataclass
class OIDCState:
    id: str
    flow_type: str = "pending"
    redirect_uri: str = "/"
    user_details: UserDetails | None = None
    ip_address: str | None = None
    expiration: datetime | None = None
    
    def is_expired(self) -> bool:
        if self.expiration is None:
            return False
        return self.expiration < datetime.now()

    @classmethod
    def init_from_dict(cls, data: Dict[str, Any]) -> OIDCState: 
        flow_type = data.get("flow_type", "pending")
        flow_classes = {   
            "device_waiting": OIDCDeviceWaiting,
            "redirect": OIDCRedirectState,
            "pending": OIDCPending,
            "device_approving": OIDCDeviceApproving,
        }
        target_class = flow_classes.get(flow_type, OIDCState)
        return target_class(**data)

@dataclass
class OIDCDeviceWaiting(OIDCState):
    flow_type: Literal["device_waiting"] = "device_waiting"
    
    status: Literal["pending", "ready", "expired", "denied"] = "pending"
    user_code: str | None = None
    verification_uri: str | None = None
    device_code: str | None = None
    expires_in: int | None = None
    interval: int | None = None
    started_at: int | None = None

@dataclass
class OIDCRedirectState(OIDCState):
    flow_type: Literal["redirect", "device_approving"] = "redirect"

@dataclass
class OIDCPending(OIDCState):
    '''
    State for client directed to welcome screen to choose a flow mode
    '''
    flow_type: Literal["pending"] = "pending"

@dataclass
class OIDCDeviceApproving(OIDCRedirectState):
    flow_type: Literal["device_approving"] = "device_approving"
    device_code: str | None = None
    current_device_code_attempt: int | None = 0