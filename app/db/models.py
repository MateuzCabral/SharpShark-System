from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, Boolean, DateTime, Enum
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime, timezone
import uuid

db = create_engine("sqlite:///./db/database.db")

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)

    def __init__(self, name: str, password: str, is_active: bool = True, is_superuser: bool = False):
        self.name = name
        self.password = password
        self.is_active = is_active
        self.is_superuser = is_superuser

    files = relationship("File", back_populates="user", cascade="all, delete-orphan")
    analysis = relationship("Analysis", back_populates="user", cascade="all, delete-orphan")
    custom_rules = relationship("CustomRule", back_populates="user", cascade="all, delete-orphan")

class File(Base):
    __tablename__ = "files"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    file_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_size = Column(Float, nullable=False)
    file_hash = Column(String, unique=True, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.now(tz=timezone.utc))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)

    analysis = relationship("Analysis", back_populates="file", cascade="all, delete-orphan")
    user = relationship("User")

    def __init__(self, file_name: str, file_path: str, file_size: float, file_hash: str, user_id: str):
        self.file_name = file_name
        self.file_path = file_path
        self.file_size = file_size
        self.file_hash = file_hash
        self.user_id = user_id


class Analysis(Base):
    __tablename__ = "analysis"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    status = Column(Enum("pending", "in_progress", "completed", "failed"), default="pending")
    total_packets = Column(Integer, default=0)
    total_streams = Column(Integer, default=0)
    duration = Column(Float, default=0.0)
    analyzed_at = Column(DateTime, default=datetime.now(tz=timezone.utc))
    file_id = Column(String, ForeignKey("files.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)

    file = relationship("File", back_populates="analysis")
    streams = relationship("Stream", back_populates="analysis", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="analysis", cascade="all, delete-orphan")
    stats = relationship("Stat", back_populates="analysis", cascade="all, delete-orphan")
    ips = relationship("IpRecord", back_populates="analysis", cascade="all, delete-orphan")
    user = relationship("User")

    def __init__(self, file_id: str, user_id: str, status: str = "pending", total_packets: int = 0, total_streams: int = 0, duration: float = 0.0):
        self.file_id = file_id
        self.user_id = user_id
        self.status = status
        self.total_packets = total_packets
        self.total_streams = total_streams
        self.duration = duration

class Stream(Base):
    __tablename__ = "streams"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String, ForeignKey("analysis.id"), nullable=False)
    stream_number = Column(Integer, nullable=False)
    preview = Column(String)
    content_path = Column(String, nullable=False)

    analysis = relationship("Analysis", back_populates="streams")
    alerts = relationship("Alert", back_populates="stream")

    def __init__(self, analysis_id: str, stream_number: int, content_path: str, preview: str = ""):
        self.analysis_id = analysis_id
        self.stream_number = stream_number
        self.content_path = content_path
        self.preview = preview


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String, ForeignKey("analysis.id"), nullable=False)
    stream_id = Column(String, ForeignKey("streams.id"), nullable=True)
    alert_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    src_ip = Column(String)
    dst_ip = Column(String)
    port = Column(Integer)
    protocol = Column(String)
    evidence = Column(String)

    analysis = relationship("Analysis", back_populates="alerts")
    stream = relationship("Stream", back_populates="alerts")

    def __init__(self, analysis_id: str, alert_type: str, severity: str, src_ip: str = "", dst_ip: str = "", port: int = None, protocol: str = "", evidence: str = ""):
        self.analysis_id = analysis_id
        self.alert_type = alert_type
        self.severity = severity
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.port = port
        self.protocol = protocol
        self.evidence = evidence

class Stat(Base):
    __tablename__ = "stats"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String, ForeignKey("analysis.id"), nullable=False)
    category = Column(String, nullable=False)
    key = Column(String, nullable=False)
    count = Column(Integer, default=0)
    
    analysis = relationship("Analysis", back_populates="stats")
    
    def __init__(self, analysis_id: str, category: str, key: str, count: int = 0):
        self.analysis_id = analysis_id
        self.category = category
        self.key = key
        self.count = count

class IpRecord(Base):
    __tablename__ = "ip_records"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String, ForeignKey("analysis.id"), nullable=False)
    ip = Column(String, nullable=False)
    role = Column(String, nullable=False)
    count = Column(Integer, default=0)
    
    analysis = relationship("Analysis", back_populates="ips")

    def __init__(self, analysis_id: str, ip: str, role: str, count: int = 0, hostname: str = "unknown", city: str = "unknown", region: str = "unknown", country: str = "unknown", organization: str = "unknown"):
        self.analysis_id = analysis_id
        self.ip = ip
        self.role = role
        self.count = count

class Setting(Base):
    __tablename__ = "settings"
    key = Column(String, primary_key=True, unique=True, nullable=False)
    value = Column(String, nullable=True)
    
    def __init__(self, key: str, value: str | None = None):
        self.key = key
        self.value = value

class CustomRule(Base):
    __tablename__ = "custom_rules"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    rule_type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    alert_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    
    user = relationship("User", back_populates="custom_rules")
    
    def __init__(self, user_id: str, name: str, rule_type: str, value: str, alert_type: str, severity: str):
        self.user_id = user_id
        self.name = name
        self.rule_type = rule_type
        self.value = value
        self.alert_type = alert_type
        self.severity = severity