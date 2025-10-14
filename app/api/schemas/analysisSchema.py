from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class StreamRead(BaseModel):
    id: str
    stream_number: int
    content_path: str
    preview: Optional[str]

    class Config:
        from_attributes = True

class AlertRead(BaseModel):
    id: str
    alert_type: str
    severity: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    evidence: Optional[str]

    class Config:
        from_attributes = True

class StatRead(BaseModel):
    id: str
    category: str
    key: str
    count: int

    class Config:
        from_attributes = True

class IpRecordRead(BaseModel):
    id: str
    ip: str
    role: str
    count: int
    hostname: str
    city: str
    region: str
    country: str
    organization: str

    class Config:
        from_attributes = True

class AnalysisRead(BaseModel):
    id: str
    file_id: str
    status: str
    total_packets: int
    total_streams: int
    duration: float
    analyzed_at: Optional[datetime]
    streams: Optional[List[StreamRead]] = []
    alerts: Optional[List[AlertRead]] = []
    stats: Optional[List[StatRead]] = []
    ips: Optional[List[IpRecordRead]] = []

    class Config:
        from_attributes = True
