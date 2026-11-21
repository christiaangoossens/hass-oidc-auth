"""OIDC Session state models"""
from warnings import deprecated
from datetime import datetime
from custom_components.auth_oidc.tools.types import UserDetails
from dataclasses import dataclass
from pydantic import BaseModel, Field
from typing import Dict, Any, Literal, Annotated, Union

class OIDCState(BaseModel):
    id: str
    flow_type: Literal["pending", "redirect", "device_waiting", "device_approving"] = Field(default="pending")
    redirect_uri: str = Field(default="/")
    user_details: UserDetails | None = Field(default=None)
    ip_address: str | None = Field(default=None)
    expiration: datetime | None = Field(default=None)

    def is_expired(self) -> bool:
        if self.expiration is None:
            return False
        return self.expiration < datetime.now()

    @deprecated("use Pydantic.TypeAdapter instead") # TODO: Remove this function before submission
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
    


class OIDCDeviceWaiting(OIDCState):
    # pyrefly: ignore[bad-override-mutable-attribute]
    flow_type: Literal["device_waiting"] = "device_waiting" 

    status: Literal["pending", "ready", "expired", "denied"] = "pending"
    user_code: str | None = None
    verification_uri: str | None = None
    device_code: str | None = None
    expires_in: int | None = None
    interval: int | None = None
    started_at: int | None = None


class OIDCRedirectState(OIDCState):
    # pyrefly: ignore[bad-override-mutable-attribute]
    flow_type: Literal["redirect", "device_approving"] = "redirect"


class OIDCPending(OIDCState):
    """
    State for client directed to welcome screen to choose a flow mode
    """

    # pyrefly: ignore[bad-override-mutable-attribute]
    flow_type: Literal["pending"] = "pending"


class OIDCDeviceApproving(OIDCRedirectState):
    # pyrefly: ignore[bad-override-mutable-attribute]
    flow_type: Literal["device_approving"] = "device_approving"
    device_code: str | None = None
    current_device_code_attempt: int | None = 0

OIDCStateTypes = Annotated[
    Union[
        OIDCPending, OIDCRedirectState, OIDCDeviceWaiting, OIDCDeviceApproving
    ],
    Field(discriminator="flow_type")
]