import os
import asyncio
import time
import pyshark
from pyshark.capture.capture import TSharkCrashException
import logging
from sqlalchemy.orm import Session
from sqlalchemy import exc as sqlalchemy_exc
from typing import Dict, Tuple
from db.models import Analysis, Stream, Stat, IpRecord, File, Alert
from db.models import CustomRule
from datetime import datetime, timezone
from core.config import UPLOAD_DIRECTORY
from analysis_rules import RulesEngine

UPLOAD_DIR = UPLOAD_DIRECTORY
STREAMS_DIR = os.path.join(UPLOAD_DIR, "streams")
os.makedirs(STREAMS_DIR, exist_ok=True)
logger = logging.getLogger("sharpshark.analysis")

SUSPECT_CHARS_SET = set(
    list(range(0x00, 0x09)) + [0x0B, 0x0C] + list(range(0x0E, 0x20)) + list(range(0x80, 0x100))
)
SUSPECT_THRESHOLD_PERCENT = 15.0

def is_payload_readable(payload: bytes) -> bool:
    if not payload: return False
    total_len = len(payload)
    if total_len == 0: return False
    try:
        payload.decode('utf-8', errors='strict')
        return True
    except UnicodeDecodeError: pass
    except Exception: pass
    suspect_count = sum(1 for byte in payload if byte in SUSPECT_CHARS_SET)
    suspect_percentage = (suspect_count / total_len) * 100
    return suspect_percentage <= SUSPECT_THRESHOLD_PERCENT

def _initialize_analysis_state(session: Session, analysis_id: str) -> Tuple[RulesEngine, Dict, Dict, Dict, Dict, Dict]:
    logger.info(f"Análise {analysis_id}: Carregando regras globais...")
    all_rules = session.query(CustomRule).all()
    payload_rules = [r for r in all_rules if r.rule_type == 'payload']
    port_rules = [r for r in all_rules if r.rule_type == 'port']
    logger.info(f"Análise {analysis_id}: Regras carregadas ({len(payload_rules)} payload, {len(port_rules)} porta).")

    rules_engine = RulesEngine(
        analysis_id=analysis_id,
        custom_payload_rules=payload_rules,
        custom_port_rules=port_rules
    )
    
    protocol_counts: Dict[str, int] = {}
    port_counts: Dict[int, int] = {}
    src_ip_counts: Dict[str, int] = {}
    dst_ip_counts: Dict[str, int] = {}
    streams_map: Dict[str, Dict] = {}
    
    return rules_engine, protocol_counts, port_counts, src_ip_counts, dst_ip_counts, streams_map

def _process_packet_capture(
    pcap_path: str, rules_engine: RulesEngine, protocol_counts: Dict, port_counts: Dict,
    src_ip_counts: Dict, dst_ip_counts: Dict, streams_map: Dict, session: Session
) -> int:
    total_packets = 0
    analysis_id = rules_engine.analysis_id
    try:
        capture = pyshark.FileCapture(pcap_path, keep_packets=False, use_json=True, include_raw=True)
        logger.info(f"Análise {analysis_id}: Iniciando captura de pacotes de {pcap_path}")

        for pkt_index, pkt in enumerate(capture):
            total_packets = pkt_index + 1
            try:
                info = rules_engine._extract_packet_info(pkt)
                new_alerts = rules_engine.process_packet(pkt)

                proto_str = info['proto']
                protocol_counts[proto_str] = protocol_counts.get(proto_str, 0) + 1

                src, dst = info['src_ip'], info['dst_ip']
                if src: src_ip_counts[src] = src_ip_counts.get(src, 0) + 1
                if dst: dst_ip_counts[dst] = dst_ip_counts.get(dst, 0) + 1

                sport, dport = info['src_port'], info['dst_port']
                if sport: port_counts[sport] = port_counts.get(sport, 0) + 1
                if dport: port_counts[dport] = port_counts.get(dport, 0) + 1

                stream_key = f"tcp-{pkt.tcp.stream}" if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'stream') else \
                             f"{src}:{sport}-{dst}:{dport}" if all([src, dst, sport, dport]) else f"pkt-{total_packets}"
                
                if stream_key not in streams_map:
                    streams_map[stream_key] = {
                        "packets": [], 
                        "stream_number": len(streams_map) + 1, 
                        "is_encrypted": False,
                        "src_ip": src,
                        "dst_ip": dst,
                        "src_port": sport,
                        "dst_port": dport,
                        "proto": info['proto']
                    }
                
                if pkt.highest_layer == "TLS": streams_map[stream_key]["is_encrypted"] = True
                
                if new_alerts:
                    if "pending_alerts" not in streams_map[stream_key]: streams_map[stream_key]["pending_alerts"] = []
                    streams_map[stream_key]["pending_alerts"].extend(new_alerts)
                
                payload_bytes = info['payload']
                
                streams_map[stream_key]["packets"].append({"payload": payload_bytes})

                if total_packets % 1000 == 0:
                    logger.debug(f"Análise {analysis_id}: Pacote {total_packets}. Committing sessão parcial...")
                    session.commit()

            except AttributeError as ae:
                logger.warning(f"Análise {analysis_id}: Atributo faltando no pacote {total_packets}. Ignorando erro: {ae}. Detalhes: {pkt.summary}")
                continue
            except ValueError as ve:
                logger.warning(f"Análise {analysis_id}: Erro de valor processando payload/campos do pacote {total_packets}: {ve}. Pulando pacote.")
                continue
            except Exception as e_pkt:
                logger.error(f"Análise {analysis_id}: Erro inesperado processando pacote {total_packets}: {e_pkt}. Pulando pacote.", exc_info=True)
                continue

        capture.close()
        logger.info(f"Análise {analysis_id}: Captura concluída. Total de {total_packets} pacotes.")

    except TSharkCrashException as e:
        logger.error(f"Análise {analysis_id}: TShark crashou durante a captura: {e}")
        raise RuntimeError(f"TShark crashou: {e}")
    except FileNotFoundError as e:
        logger.error(f"Análise {analysis_id}: Arquivo PCAP não encontrado em {pcap_path}: {e}")
        raise
    except Exception as e:
        logger.exception(f"Análise {analysis_id}: Erro fatal inesperado durante a captura de pacotes: {e}")
        raise

    return total_packets

def _save_analysis_streams(session: Session, analysis_id: str, streams_map: Dict, rules_engine: RulesEngine) -> int:
    stream_count = 0
    logger.info(f"Análise {analysis_id}: Iniciando salvamento de {len(streams_map)} streams potenciais...")
    processed_streams = 0

    for stream_key, meta in streams_map.items():
        processed_streams += 1
        stream_number_log = meta.get("stream_number", "N/A")

        if processed_streams % 100 == 0:
            logger.debug(f"Análise {analysis_id}: Processando stream {processed_streams}/{len(streams_map)}...")

        if meta.get("is_encrypted", False): continue
        
        full_payload = b"".join(p["payload"] for p in meta["packets"] if p.get("payload"))
        
        if not full_payload or not is_payload_readable(full_payload): continue
        
        packet_based_alerts = meta.get("pending_alerts", [])

        stream_based_alerts = []
        try:
            stream_based_alerts = rules_engine.process_stream(
                full_payload=full_payload,
                stream_meta=meta
            )
            if stream_based_alerts:
                logger.info(f"Análise {analysis_id}: Nov(o/s) {len(stream_based_alerts)} alerta(s) encontrado(s) na análise do stream {stream_number_log}")
        except Exception as e_rule_stream:
            logger.warning(f"Análise {analysis_id}: Erro ao rodar regras de stream no stream {stream_number_log}: {e_rule_stream}")
        
        all_alerts_for_this_stream = packet_based_alerts + stream_based_alerts
        
        final_stream_path = os.path.join(STREAMS_DIR, f"{analysis_id}_stream_{stream_count + 1}.bin")

        try:
            try:
                with open(final_stream_path, "wb") as sf:
                    sf.write(full_payload)
            except OSError as e:
                logger.error(f"Análise {analysis_id}: Falha OSError ao salvar arquivo do stream {stream_number_log} ({final_stream_path}): {e}")
                continue

            try: preview = full_payload[:200].decode('utf-8', errors='ignore')
            except Exception: preview = full_payload[:200].hex()

            new_stream = Stream(
                analysis_id=analysis_id, stream_number=meta["stream_number"],
                content_path=final_stream_path, preview=preview
            )
            session.add(new_stream)
            session.flush()

            if all_alerts_for_this_stream:
                for alert in all_alerts_for_this_stream:
                    alert.stream_id = new_stream.id
                    session.add(alert)

            stream_count += 1

        except sqlalchemy_exc.SQLAlchemyError as e:
            logger.error(f"Análise {analysis_id}: Erro DB ao salvar stream {stream_number_log} ou alertas: {e}. Rollback do stream.")
            session.rollback()
            try:
                if os.path.exists(final_stream_path): os.remove(final_stream_path)
            except OSError as rm_e:
                logger.warning(f"Análise {analysis_id}: Não remover arquivo órfão {final_stream_path}: {rm_e}")
            continue
        except Exception as e_stream:
            logger.exception(f"Análise {analysis_id}: Erro inesperado salvando stream {stream_number_log}: {e_stream}. Rollback e pulando.")
            session.rollback()
            try:
                if os.path.exists(final_stream_path): os.remove(final_stream_path)
            except OSError: pass
            continue

    logger.info(f"Análise {analysis_id}: Salvamento de streams concluído. {stream_count} streams salvos.")
    return stream_count

def _save_analysis_stats(session: Session, analysis_id: str, protocol_counts: Dict, port_counts: Dict):
    logger.info(f"Análise {analysis_id}: Adicionando estatísticas à sessão...")
    try:
        for proto, cnt in protocol_counts.items():
            session.add(Stat(analysis_id=analysis_id, category="protocol", key=proto, count=cnt))
        for port, cnt in port_counts.items():
            session.add(Stat(analysis_id=analysis_id, category="port", key=str(port), count=cnt))
        logger.info(f"Análise {analysis_id}: {len(protocol_counts)}xProtocolo, {len(port_counts)}xPorta stats adicionados.")
    except Exception as e:
        logger.exception(f"Análise {analysis_id}: Erro inesperado ao preparar stats: {e}")

def _save_analysis_ip_records(session: Session, analysis_id: str, src_ip_counts: Dict, dst_ip_counts: Dict):
    logger.info(f"Análise {analysis_id}: Adicionando registros de IP à sessão...")
    try:
        for ip, cnt in src_ip_counts.items():
            session.add(IpRecord(analysis_id=analysis_id, ip=ip, role="SRC", count=cnt))
        for ip, cnt in dst_ip_counts.items():
            session.add(IpRecord(analysis_id=analysis_id, ip=ip, role="DST", count=cnt))
        logger.info(f"Análise {analysis_id}: {len(src_ip_counts)}xSRC, {len(dst_ip_counts)}xDST IP records adicionados.")
    except Exception as e:
        logger.exception(f"Análise {analysis_id}: Erro inesperado ao preparar IP records: {e}")

def _finalize_analysis(session: Session, analysis: Analysis, total_packets: int, stream_count: int, start_time: float):
    end_time = time.perf_counter()
    analysis.status = "completed"
    analysis.total_packets = total_packets
    analysis.total_streams = stream_count
    analysis.duration = round(end_time - start_time, 3)
    analysis.analyzed_at = datetime.now(timezone.utc)
    logger.info(f"Análise {analysis.id}: Finalizada com status '{analysis.status}'. Duração: {analysis.duration}s. Pacotes: {total_packets}. Streams Salvos: {stream_count}.")

def analyze_file(session: Session, file_obj: File, analysis_id: str) -> Analysis:
    try: asyncio.get_running_loop()
    except RuntimeError: asyncio.set_event_loop(asyncio.new_event_loop())

    start_time = time.perf_counter()
    pcap_path = file_obj.file_path
    logger.info(f"Análise {analysis_id}: Iniciando análise para ficheiro {file_obj.id} ({file_obj.file_name}) em {pcap_path}")

    analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        logger.error(f"CRÍTICO: Análise {analysis_id} não encontrada no DB ao iniciar analyze_file.")
        raise RuntimeError(f"Análise {analysis_id} não encontrada.")
    if analysis.status != 'in_progress':
        logger.warning(f"Análise {analysis_id}: Status inesperado '{analysis.status}' ao iniciar. Deveria ser 'in_progress'.")
    
    try:
        rules_engine, protocol_counts, port_counts, src_ip_counts, dst_ip_counts, streams_map = \
            _initialize_analysis_state(session, analysis_id)

        total_packets = _process_packet_capture(
            pcap_path, rules_engine, protocol_counts, port_counts,
            src_ip_counts, dst_ip_counts, streams_map, session
        )

        stream_count = _save_analysis_streams(session, analysis_id, streams_map, rules_engine)
        _save_analysis_stats(session, analysis_id, protocol_counts, port_counts)
        _save_analysis_ip_records(session, analysis_id, src_ip_counts, dst_ip_counts)
        
        _finalize_analysis(session, analysis, total_packets, stream_count, start_time)

        session.commit()
        logger.info(f"Análise {analysis_id}: Commit final bem-sucedido.")

    except Exception as e:
        logger.exception(f"Análise {analysis_id}: Falha GERAL irrecuperável durante a análise: {e}")
        session.rollback()
        try:
            logger.info(f"Análise {analysis_id}: Tentando marcar status como 'failed' e salvar alerta de erro...")
            _mark_analysis_status_in_new_session(analysis_id, "failed")
            _save_error_alert_in_new_session(analysis_id, f"Erro geral na análise: {str(e)[:1990]}")
        except Exception as final_err:
            logger.error(f"Análise {analysis_id}: Falha CRÍTICA ao tentar marcar status/salvar alerta pós-falha: {final_err}")
        raise
    return analysis

def _mark_analysis_status_in_new_session(analysis_id: str, status: str):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    try:
        db_engine = create_engine("sqlite:///./db/database.db")
        SessionLocalNew = sessionmaker(bind=db_engine)
        session_new = SessionLocalNew()
        try:
            analysis = session_new.query(Analysis).filter(Analysis.id == analysis_id).first()
            if analysis:
                if analysis.status != status:
                    analysis.status = status
                    session_new.commit()
                    logger.info(f"Análise {analysis_id}: Status atualizado para '{status}' (sessão separada).")
                else:
                    logger.info(f"Análise {analysis_id}: Status já era '{status}' (sessão separada). Nenhuma alteração.")
            else:
                logger.warning(f"Análise {analysis_id}: Status '{status}' não atualizado (análise não encontrada em sessão separada).")
        except sqlalchemy_exc.SQLAlchemyError as db_e:
            logger.error(f"Análise {analysis_id}: Falha DB ao atualizar status para '{status}' (sessão separada): {db_e}")
            session_new.rollback()
        finally:
            session_new.close()
    except Exception as e:
        logger.error(f"Análise {analysis_id}: Falha ao criar sessão separada para marcar status '{status}': {e}")


def _save_error_alert_in_new_session(analysis_id: str, evidence: str):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    try:
        db_engine = create_engine("sqlite:///./db/database.db")
        SessionLocalNew = sessionmaker(bind=db_engine)
        session_new = SessionLocalNew()
        try:
            existing_alert = session_new.query(Alert.id).filter(
                Alert.analysis_id == analysis_id,
                Alert.alert_type == "analysis_error"
            ).first()

            if not existing_alert:
                fail_alert = Alert(analysis_id=analysis_id, alert_type="analysis_error", severity="critical", evidence=evidence)
                session_new.add(fail_alert)
                session_new.commit()
                logger.info(f"Análise {analysis_id}: Alerta de erro salvo no DB (sessão separada).")
            else:
                logger.info(f"Análise {analysis_id}: Alerta de erro já existia. Nenhuma alteração (sessão separada).")

        except sqlalchemy_exc.SQLAlchemyError as db_e:
            logger.error(f"Análise {analysis_id}: Falha DB ao salvar alerta de erro (sessão separada): {db_e}")
            session_new.rollback()
        finally:
            session_new.close()
    except Exception as e:
        logger.error(f"Análise {analysis_id}: Falha ao criar sessão separada para salvar alerta de erro: {e}")