from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from api.schemas.dependencies import get_session, require_active_user
from services.alerts import get_alerts
from db.models import User

# Define um roteador para a seção de Alertas da API
alert_router = APIRouter(prefix="/alerts", tags=["Alerts"])

@alert_router.get("/")
def list_alerts(
    # Parâmetros de query opcionais para filtrar os alertas
    alert_type: str = Query(None),
    severity: str = Query(None),
    current_user: User = Depends(require_active_user),
    # Injeta a sessão do banco de dados (via dependência)
    session: Session = Depends(get_session)
):
    """
    Endpoint para listar todos os alertas, com filtros opcionais
    por tipo de alerta e severidade.
    """
    # Delega a lógica de busca para a camada de serviço (services.alerts)
    return get_alerts(session, alert_type, severity)