from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from api.schemas.fileSchema import FileReadSimple 

class AlertRead(BaseModel):
    id: str
    stream_id: Optional[str] = None
    analysis_id: str
    alert_type: str
    severity: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    evidence: Optional[str]

    class Config:
        from_attributes = True

class StreamRead(BaseModel):
    id: str
    stream_number: int
    content_path: str
    preview: Optional[str]
    alerts: Optional[List[AlertRead]] = [] 

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
    file: Optional[FileReadSimple] = None 
    streams: Optional[List[StreamRead]] = [] 
    
    class Config:
        from_attributes = True