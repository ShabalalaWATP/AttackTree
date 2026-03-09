from pydantic import BaseModel
from typing import Optional, Any
from datetime import datetime


class LLMProviderConfigCreate(BaseModel):
    name: str = "Local LLM"
    base_url: str = "http://localhost:11434/v1"
    api_key: str = ""
    model: str = ""
    custom_headers: dict[str, str] = {}
    timeout: int = 120
    stream_enabled: bool = False
    tls_verify: bool = True
    ca_bundle_path: str = ""
    client_cert_path: str = ""
    client_key_path: str = ""


class LLMProviderConfigUpdate(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    custom_headers: Optional[dict[str, str]] = None
    timeout: Optional[int] = None
    stream_enabled: Optional[bool] = None
    tls_verify: Optional[bool] = None
    ca_bundle_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None


class LLMProviderConfigResponse(BaseModel):
    id: str
    name: str = ""
    base_url: str = ""
    has_api_key: bool = False
    model: str = ""
    custom_headers: dict[str, str] = {}
    timeout: int = 120
    stream_enabled: bool = False
    tls_verify: bool = True
    ca_bundle_path: str = ""
    client_cert_path: str = ""
    client_key_path: str = ""
    is_active: bool = True
    last_tested_at: Optional[datetime] = None
    last_test_result: str = ""
    last_test_message: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
