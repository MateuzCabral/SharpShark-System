from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

# Schemas Pydantic definem a forma dos dados de entrada (request) e saída (response)
# Eles fazem a validação automática dos tipos de dados.

class AlertRead(BaseModel):
    """ Schema para 'ler' (retornar) um Alerta. """
    id: str
    stream_id: Optional[str] = None 
    alert_type: str
    severity: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    evidence: Optional[str]

    class Config:
        # Permite que o Pydantic leia os dados a partir de um modelo SQLAlchemy
        # (ex: lendo 'alert.id' em vez de 'alert["id"]')
        from_attributes = True

class StreamRead(BaseModel):
    """ Schema para 'ler' um Stream. """
    id: str
    stream_number: int
    content_path: str
    preview: Optional[str]
    alerts: Optional[List[AlertRead]] = [] # Lista de alertas aninhados

    class Config:
        from_attributes = True

class StatRead(BaseModel):
    """ Schema para 'ler' uma Estatística. """
    id: str
    category: str
    key: str
    count: int

    class Config:
        from_attributes = True

class IpRecordRead(BaseModel):
    """ Schema para 'ler' um Registro de IP. """
    id: str
    ip: str
    role: str # (ex: 'src' ou 'dst')
    count: int

    class Config:
        from_attributes = True

class AnalysisRead(BaseModel):
    """ Schema principal para 'ler' uma Análise. """
    id: str
    file_id: str
    status: str
    total_packets: int
    total_streams: int
    duration: float
    analyzed_at: Optional[datetime]
    
    # Relacionamentos aninhados que serão carregados (graças ao 'joinedload' nas rotas)
    streams: Optional[List[StreamRead]] = [] 
    alerts: Optional[List[AlertRead]] = [] 
    stats: Optional[List[StatRead]] = [] 
    ips: Optional[List[IpRecordRead]] = [] 

    class Config:
        from_attributes = True