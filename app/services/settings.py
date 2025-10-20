from sqlalchemy.orm import Session
from db.models import Setting
from typing import List, Optional

INGEST_FOLDER_KEY = "INGEST_FOLDER"
INGEST_USER_ID_KEY = "INGEST_USER_ID"
INGEST_PROJECT_NAME_KEY = "INGEST_PROJECT_NAME"

def get_setting(session: Session, key: str) -> Optional[str]:
    setting = session.query(Setting).filter(Setting.key == key).first()
    if setting:
        return setting.value
    return None

def set_setting(session: Session, key: str, value: str) -> Setting:
    setting = session.query(Setting).filter(Setting.key == key).first()
    if setting:
        setting.value = value
    else:
        setting = Setting(key=key, value=value)
        session.add(setting)
    session.commit()
    session.refresh(setting)
    return setting

def get_all_settings(session: Session) -> List[Setting]:
    return session.query(Setting).all()