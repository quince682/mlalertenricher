# fastapi_app/models.py
from pydantic import BaseModel, Field
from typing import Optional, Literal

class ESConfig(BaseModel):
    auth_method: Literal["no_security", "ssl", "api_key"]
    # Common fields
    host: str = Field(..., description="Elasticsearch host, IP, or URL")
    # No Security / SSL fields
    port: Optional[int] = Field(None, description="Elasticsearch port number")
    # SSL-specific fields
    username: Optional[str] = Field(None, description="Username for SSL/TLS auth")
    password: Optional[str] = Field(None, description="Password for SSL/TLS auth")
    # API Key-specific field
    api_key: Optional[str] = Field(None, description="API Key for authentication")

