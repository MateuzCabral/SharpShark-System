from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from datetime import datetime, timedelta, timezone
import traceback # Para logar erros
from db.models import Stat, Analysis, Alert, IpRecord # Importar modelos

def get_aggregated_stats(session: Session, category: str = None):
    """
    Busca estatísticas agregadas, agrupadas por categoria e chave.
    (Esta função não precisa de alteração de fuso horário)
    """
    query = session.query(
        Stat.category,
        Stat.key,
        func.sum(Stat.count).label('total_count')
    )
    if category:
        query = query.filter(Stat.category == category)

    results = query.group_by(Stat.category, Stat.key)\
                   .order_by(Stat.category, func.sum(Stat.count).desc())\
                   .all()

    formatted_stats = {}
    for cat, key, count in results:
        if cat not in formatted_stats:
            formatted_stats[cat] = []
        formatted_stats[cat].append({"key": key, "count": count or 0})

    if category:
        return formatted_stats.get(category, [])
    return formatted_stats


def get_stats_for_analysis(session: Session, analysis_id: str) -> list[Stat]:
    """
    Busca todos os objetos Stat associados a uma análise específica.
    """
    return session.query(Stat).filter(Stat.analysis_id == analysis_id).all()


def calculate_dashboard_summary(session: Session) -> dict:
    """
    Calcula as estatísticas agregadas necessárias para o dashboard principal.
    """
    try:
        # 1. Total de Pacotes (soma de todas as análises completas)
        total_packets_result = session.query(func.sum(Analysis.total_packets))\
                                      .filter(Analysis.status == 'completed')\
                                      .scalar()
        total_packets = total_packets_result or 0

        # 2. Total de Alertas Registrados
        total_alerts = session.query(func.count(Alert.id)).scalar() or 0

        # 3. IPs Únicos Vistos
        unique_ips = session.query(func.count(distinct(IpRecord.ip))).scalar() or 0

        # 4. Análises Concluídas
        completed_analyses = session.query(func.count(Analysis.id))\
                                     .filter(Analysis.status == 'completed')\
                                     .scalar() or 0

        # 5. Tráfego por Hora (Pacotes das análises concluídas nas últimas 24h)
        utc_now = datetime.now(timezone.utc)
        twenty_four_hours_ago = utc_now - timedelta(hours=24)

        # Define o fuso horário do Brasil (UTC-3)
        br_tz = timezone(timedelta(hours=-3))
        # Pega o 'agora' no fuso do Brasil para gerar as chaves do dicionário
        now_in_brazil = utc_now.astimezone(br_tz) 

        # Query para agrupar pacotes por slot de hora, APLICANDO O OFFSET DE -3 HORAS
        traffic_data = session.query(
            func.strftime('%H:00', Analysis.analyzed_at, '-3 hours').label('hour_slot'),
            func.sum(Analysis.total_packets).label('total_packets_in_hour')
        ).filter(
            Analysis.status == 'completed',
            Analysis.analyzed_at >= twenty_four_hours_ago # O filtro de 24h continua sendo UTC
        ).group_by('hour_slot').order_by('hour_slot').all()

        # Preenche todos os slots de hora (agora em UTC-3, pois 'now_in_brazil' está em UTC-3)
        hourly_traffic = { (now_in_brazil - timedelta(hours=h)).strftime("%H:00"): 0 for h in range(24) }
        
        # Atualiza com os dados do banco (que agora também estão em UTC-3)
        for hour_slot, packets in traffic_data:
             if hour_slot in hourly_traffic:
                 hourly_traffic[hour_slot] += packets if packets else 0

        # Formata e ordena para o gráfico
        traffic_last_24h = sorted(
             [{"time": hour, "packets": count} for hour, count in hourly_traffic.items()],
             key=lambda x: x['time']
        )

        # 6. Distribuição de Protocolos (Top 5 + Outros)
        top_protocols = session.query(Stat.key, func.sum(Stat.count).label('total_count')) \
                             .filter(Stat.category == 'protocol') \
                             .group_by(Stat.key) \
                             .order_by(func.sum(Stat.count).desc()) \
                             .limit(5) \
                             .all()

        protocol_distribution = [{"name": key, "value": count or 0} for key, count in top_protocols]

        # Calcula "Outros" se necessário
        if len(protocol_distribution) > 0:
            total_protocol_count_result = session.query(func.sum(Stat.count))\
                                                 .filter(Stat.category == 'protocol')\
                                                 .scalar()
            total_protocol_count = total_protocol_count_result or 0
            top_5_count = sum(p['value'] for p in protocol_distribution)
            others_count = total_protocol_count - top_5_count

            if others_count > 0 and len(protocol_distribution) == 5:
                protocol_distribution.append({"name": "Outros", "value": others_count})
            elif others_count <= 0 and any(p['name'] == 'Outros' for p in protocol_distribution):
                 protocol_distribution = [p for p in protocol_distribution if p['name'] != 'Outros']

        # Monta o dicionário final de resposta
        return {
            "totalPackets": {"value": total_packets},
            "activeAlerts": {"value": total_alerts},
            "uniqueIPs": {"value": unique_ips},
            "completedAnalyses": {"value": completed_analyses},
            "trafficLast24h": traffic_last_24h,
            "protocolDistribution": protocol_distribution
        }
    except Exception as e:
        # Loga o erro e relança para ser tratado pela rota (que retornará 500)
        print(f"Erro ao calcular sumário do dashboard no serviço:")
        traceback.print_exc()
        raise e # Relança a exceção original
