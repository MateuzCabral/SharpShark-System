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

class File(Base):
    __tablename__ = "files"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    file_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_size = Column(Float, nullable=False)
    file_hash = Column(String, unique=True, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.now(tz=timezone.utc))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)

    analysis = relationship("Analysis", back_populates="file")
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

    file = relationship("File", back_populates="analysis")

    def __init__(self, file_id: str, status: str = "pending", total_packets: int = 0, total_streams: int = 0, duration: float = 0.0):
        self.file_id = file_id
        self.status = status
        self.total_packets = total_packets
        self.total_streams = total_streams
        self.duration = duration
