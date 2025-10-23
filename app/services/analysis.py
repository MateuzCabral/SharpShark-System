import os
import asyncio
import time
import pyshark  # Wrapper Python para o TShark (Wireshark CLI)
from pyshark.capture.capture import TSharkCrashException
import string
import logging
from sqlalchemy.orm import Session
from sqlalchemy import exc as sqlalchemy_exc
from typing import Dict, Tuple
from db.models import Analysis, Stream, Stat, IpRecord, File, Alert
from db.models import CustomRule
from datetime import datetime, timezone
from core.config import UPLOAD_DIRECTORY
from analysis_rules import RulesEngine  # Importa o motor de regras de segurança

# Configuração de diretórios e logger
UPLOAD_DIR = UPLOAD_DIRECTORY
STREAMS_DIR = os.path.join(UPLOAD_DIR, "streams")
os.makedirs(STREAMS_DIR, exist_ok=True)
logger = logging.getLogger("sharpshark.analysis")

# --- Heurística para detecção de payload legível ---
# Define um conjunto de caracteres "suspeitos" (não-imprimíveis, controle, etc.)
SUSPECT_CHARS_SET = set(
    list(range(0x00, 0x09)) + [0x0B, 0x0C] + list(range(0x0E, 0x20)) + list(range(0x80, 0x100))
)
# Limite de porcentagem de caracteres suspeitos para considerar um payload como "não legível"
SUSPECT_THRESHOLD_PERCENT = 15.0

def is_payload_readable(payload: bytes) -> bool:
    """
    Verifica se um payload de bytes é provavelmente legível (texto) ou binário/criptografado.
    1. Tenta decodificar como UTF-8 estrito.
    2. Se falhar, calcula a porcentagem de caracteres "suspeitos".
    """
    if not payload: return False
    total_len = len(payload)
    if total_len == 0: return False
    
    # 1. Tentativa de decodificação rápida (UTF-8)
    try:
        payload.decode('utf-8', errors='strict')
        return True  # É UTF-8 válido, então é legível
    except UnicodeDecodeError: pass
    except Exception: pass
    
    # 2. Análise heurística de bytes
    suspect_count = sum(1 for byte in payload if byte in SUSPECT_CHARS_SET)
    suspect_percentage = (suspect_count / total_len) * 100
    
    # Se a porcentagem de suspeitos for baixa, consideramos legível
    return suspect_percentage <= SUSPECT_THRESHOLD_PERCENT

def _initialize_analysis_state(session: Session, analysis_id: str) -> Tuple[RulesEngine, Dict, Dict, Dict, Dict, Dict]:
    """
    Prepara o estado inicial para uma nova análise.
    Carrega regras, inicializa o RulesEngine e os dicionários de contagem.
    """
    logger.info(f"Análise {analysis_id}: Carregando regras globais...")
    all_rules = session.query(CustomRule).all()
    payload_rules = [r for r in all_rules if r.rule_type == 'payload']
    port_rules = [r for r in all_rules if r.rule_type == 'port']
    logger.info(f"Análise {analysis_id}: Regras carregadas ({len(payload_rules)} payload, {len(port_rules)} porta).")

    # Inicializa o motor de regras com as regras customizadas
    rules_engine = RulesEngine(
        analysis_id=analysis_id,
        custom_payload_rules=payload_rules,
        custom_port_rules=port_rules
    )
    
    # Dicionários para armazenar estatísticas
    protocol_counts: Dict[str, int] = {}
    port_counts: Dict[int, int] = {}
    src_ip_counts: Dict[str, int] = {}
    dst_ip_counts: Dict[str, int] = {}
    
    # Dicionário principal para remontagem de streams
    # Key: 'tcp-stream-index' ou 'ip:port-ip:port'
    # Value: { "packets": [], "stream_number": int, "is_encrypted": bool, "pending_alerts": [] }
    streams_map: Dict[str, Dict] = {}
    
    return rules_engine, protocol_counts, port_counts, src_ip_counts, dst_ip_counts, streams_map

def _process_packet_capture(
    pcap_path: str, rules_engine: RulesEngine, protocol_counts: Dict, port_counts: Dict,
    src_ip_counts: Dict, dst_ip_counts: Dict, streams_map: Dict, session: Session
) -> int:
    """
    Função principal de processamento. Lê o PCAP pacote a pacote usando PyShark.
    """
    total_packets = 0
    analysis_id = rules_engine.analysis_id
    try:
        # Abre o arquivo de captura
        # keep_packets=False: economiza memória, não mantém pacotes no objeto 'capture'
        # use_json=True, include_raw=True: necessário para PyShark obter todos os campos e payload
        capture = pyshark.FileCapture(pcap_path, keep_packets=False, use_json=True, include_raw=True)
        logger.info(f"Análise {analysis_id}: Iniciando captura de pacotes de {pcap_path}")

        # Itera sobre cada pacote no arquivo
        for pkt_index, pkt in enumerate(capture):
            total_packets = pkt_index + 1
            try:
                # 1. Processa o pacote no motor de regras de segurança
                # 'new_alerts' são alertas que ainda não foram associados a um Stream ID
                new_alerts = rules_engine.process_packet(pkt)

                # 2. Coleta de Estatísticas (Protocolo)
                proto = pkt.highest_layer
                # Lógica para encontrar o protocolo mais relevante
                if not proto or str(proto).lower() == 'data':
                    if hasattr(pkt, 'tcp'): proto = 'TCP'
                    elif hasattr(pkt, 'udp'): proto = 'UDP'
                    elif hasattr(pkt, 'arp'): proto = 'ARP'
                    elif hasattr(pkt, 'icmp'): proto = 'ICMP'
                    elif hasattr(pkt, 'ip'): proto = 'IP'
                    else: proto = next((lay.layer_name for lay in pkt.layers), "UNKNOWN")
                proto_str = str(proto).upper().replace('_RAW', '') # Limpa o nome
                protocol_counts[proto_str] = protocol_counts.get(proto_str, 0) + 1

                # 3. Coleta de Estatísticas (IPs)
                src, dst = (pkt.ip.src, pkt.ip.dst) if hasattr(pkt, 'ip') else \
                           (pkt.ipv6.src, pkt.ipv6.dst) if hasattr(pkt, 'ipv6') else (None, None)
                if src: src_ip_counts[src] = src_ip_counts.get(src, 0) + 1
                if dst: dst_ip_counts[dst] = dst_ip_counts.get(dst, 0) + 1

                # 4. Coleta de Estatísticas (Portas)
                sport, dport = (int(pkt.tcp.srcport), int(pkt.tcp.dstport)) if hasattr(pkt, 'tcp') else \
                               (int(pkt.udp.srcport), int(pkt.udp.dstport)) if hasattr(pkt, 'udp') else (None, None)
                if sport: port_counts[sport] = port_counts.get(sport, 0) + 1
                if dport: port_counts[dport] = port_counts.get(dport, 0) + 1

                # 5. Lógica de Remontagem de Stream
                # Tenta usar o 'stream index' do TShark (para TCP)
                stream_key = f"tcp-{pkt.tcp.stream}" if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'stream') else \
                             f"{src}:{sport}-{dst}:{dport}" if all([src, dst, sport, dport]) else f"pkt-{total_packets}" # Fallback
                
                # Inicializa o stream no mapa se for o primeiro pacote dele
                if stream_key not in streams_map:
                    streams_map[stream_key] = {"packets": [], "stream_number": len(streams_map) + 1, "is_encrypted": False}
                
                # Marca stream como criptografado (para pular salvar o payload depois)
                if pkt.highest_layer == "TLS": streams_map[stream_key]["is_encrypted"] = True
                
                # Adiciona alertas encontrados neste pacote ao stream correspondente
                if new_alerts:
                    if "pending_alerts" not in streams_map[stream_key]: streams_map[stream_key]["pending_alerts"] = []
                    streams_map[stream_key]["pending_alerts"].extend(new_alerts)
                
                # Extrai o payload (se existir)
                payload_bytes = bytes.fromhex(pkt.tcp.payload.replace(":", "")) if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload') else \
                                bytes.fromhex(pkt.udp.payload.replace(":", "")) if hasattr(pkt, 'udp') and hasattr(pkt.udp, 'payload') else b''
                
                # Armazena o payload no mapa de streams (para remontagem)
                streams_map[stream_key]["packets"].append({"payload": payload_bytes})

                # Commit parcial para longas análises (evita locks)
                if total_packets % 1000 == 0:
                    logger.debug(f"Análise {analysis_id}: Pacote {total_packets}. Committing sessão parcial...")
                    session.commit()

            # Tratamento de erros robusto para pacotes malformados ou com atributos faltando
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

def _save_analysis_streams(session: Session, analysis_id: str, streams_map: Dict) -> int:
    """
    Itera sobre os streams remontados, salva o payload em arquivos .bin
    e cria os registros de Stream e Alert no banco de dados.
    """
    stream_count = 0
    logger.info(f"Análise {analysis_id}: Iniciando salvamento de {len(streams_map)} streams potenciais...")
    processed_streams = 0

    for stream_key, meta in streams_map.items():
        processed_streams += 1
        stream_number_log = meta.get("stream_number", "N/A")

        if processed_streams % 100 == 0:
            logger.debug(f"Análise {analysis_id}: Processando stream {processed_streams}/{len(streams_map)}...")

        # Pula streams criptografados (TLS)
        if meta.get("is_encrypted", False): continue
        
        # Junta todos os payloads dos pacotes do stream
        full_payload = b"".join(p["payload"] for p in meta["packets"] if p.get("payload"))
        
        # Pula streams vazios ou que a heurística considera "não legíveis" (binários)
        if not full_payload or not is_payload_readable(full_payload): continue

        # Define o caminho do arquivo .bin que armazenará o payload
        final_stream_path = os.path.join(STREAMS_DIR, f"{analysis_id}_stream_{stream_count + 1}.bin")

        try:
            # Tenta salvar o payload no arquivo
            try:
                with open(final_stream_path, "wb") as sf:
                    sf.write(full_payload)
            except OSError as e:
                logger.error(f"Análise {analysis_id}: Falha OSError ao salvar arquivo do stream {stream_number_log} ({final_stream_path}): {e}")
                continue  # Pula este stream

            # Cria um preview (primeiros 200 bytes)
            try: preview = full_payload[:200].decode('utf-8', errors='ignore')
            except Exception: preview = full_payload[:200].hex()

            # Cria o objeto Stream para o DB
            new_stream = Stream(
                analysis_id=analysis_id, stream_number=meta["stream_number"],
                content_path=final_stream_path, preview=preview
            )
            session.add(new_stream)
            session.flush()  # Força o 'new_stream' a obter um ID

            # Associa os alertas pendentes (encontrados no _process_packet_capture)
            # ao ID do stream que acabamos de criar.
            if "pending_alerts" in meta:
                for alert in meta["pending_alerts"]:
                    alert.stream_id = new_stream.id
                    session.add(alert)

            stream_count += 1

        except sqlalchemy_exc.SQLAlchemyError as e:
            # Erro de DB: faz rollback, remove o arquivo .bin órfão e continua
            logger.error(f"Análise {analysis_id}: Erro DB ao salvar stream {stream_number_log} ou alertas: {e}. Rollback do stream.")
            session.rollback()
            try:
                if os.path.exists(final_stream_path): os.remove(final_stream_path)
            except OSError as rm_e:
                logger.warning(f"Análise {analysis_id}: Não remover arquivo órfão {final_stream_path}: {rm_e}")
            continue
        except Exception as e_stream:
            # Erro inesperado: faz rollback, remove o arquivo .bin órfão e continua
             logger.exception(f"Análise {analysis_id}: Erro inesperado salvando stream {stream_number_log}: {e_stream}. Rollback e pulando.")
             session.rollback()
             try:
                 if os.path.exists(final_stream_path): os.remove(final_stream_path)
             except OSError: pass
             continue

    logger.info(f"Análise {analysis_id}: Salvamento de streams concluído. {stream_count} streams salvos.")
    return stream_count

def _save_analysis_stats(session: Session, analysis_id: str, protocol_counts: Dict, port_counts: Dict):
    """ Salva as estatísticas (Protocolos, Portas) no banco de dados. """
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
    """ Salva os registros de IP (Origem, Destino) no banco de dados. """
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
    """ Atualiza o registro principal da Análise com os totais e status 'completed'. """
    end_time = time.perf_counter()
    analysis.status = "completed"
    analysis.total_packets = total_packets
    analysis.total_streams = stream_count
    analysis.duration = round(end_time - start_time, 3)
    analysis.analyzed_at = datetime.now(timezone.utc)
    logger.info(f"Análise {analysis.id}: Finalizada com status '{analysis.status}'. Duração: {analysis.duration}s. Pacotes: {total_packets}. Streams Salvos: {stream_count}.")

def analyze_file(session: Session, file_obj: File, analysis_id: str) -> Analysis:
    """
    Função orquestradora principal para a análise de um arquivo.
    Esta função é executada em um processo separado (via task_runner.py).
    """
    # Garante que há um loop de eventos asyncio (necessário para PyShark)
    try: asyncio.get_running_loop()
    except RuntimeError: asyncio.set_event_loop(asyncio.new_event_loop())

    start_time = time.perf_counter()
    pcap_path = file_obj.file_path
    logger.info(f"Análise {analysis_id}: Iniciando análise para ficheiro {file_obj.id} ({file_obj.file_name}) em {pcap_path}")

    # Busca o objeto 'Analysis' que já deve existir (criado em 'pending' ou 'in_progress')
    analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        logger.error(f"CRÍTICO: Análise {analysis_id} não encontrada no DB ao iniciar analyze_file.")
        raise RuntimeError(f"Análise {analysis_id} não encontrada.")
    if analysis.status != 'in_progress':
        logger.warning(f"Análise {analysis_id}: Status inesperado '{analysis.status}' ao iniciar. Deveria ser 'in_progress'.")
    
    try:
        # 1. Preparação
        rules_engine, protocol_counts, port_counts, src_ip_counts, dst_ip_counts, streams_map = \
            _initialize_analysis_state(session, analysis_id)

        # 2. Processamento (Leitura do PCAP)
        total_packets = _process_packet_capture(
            pcap_path, rules_engine, protocol_counts, port_counts,
            src_ip_counts, dst_ip_counts, streams_map, session
        )

        # 3. Salvamento (Streams, Stats, IPs)
        stream_count = _save_analysis_streams(session, analysis_id, streams_map)
        _save_analysis_stats(session, analysis_id, protocol_counts, port_counts)
        _save_analysis_ip_records(session, analysis_id, src_ip_counts, dst_ip_counts)
        
        # 4. Finalização
        _finalize_analysis(session, analysis, total_packets, stream_count, start_time)

        # Commit final da transação
        session.commit()
        logger.info(f"Análise {analysis_id}: Commit final bem-sucedido.")

    except Exception as e:
        # --- Tratamento de Falha Grave ---
        # Se qualquer etapa falhar, faz rollback da sessão atual
        logger.exception(f"Análise {analysis_id}: Falha GERAL irrecuperável durante a análise: {e}")
        session.rollback()
        try:
            # Tenta marcar a análise como 'failed' e salvar um alerta
            # usando SESSÕES NOVAS (pois a sessão atual está comprometida)
            logger.info(f"Análise {analysis_id}: Tentando marcar status como 'failed' e salvar alerta de erro...")
            _mark_analysis_status_in_new_session(analysis_id, "failed")
            _save_error_alert_in_new_session(analysis_id, f"Erro geral na análise: {str(e)[:1990]}")
        except Exception as final_err:
            # Falha ao tentar salvar o status de falha (erro crítico)
            logger.error(f"Análise {analysis_id}: Falha CRÍTICA ao tentar marcar status/salvar alerta pós-falha: {final_err}")
        raise
    return analysis

def _mark_analysis_status_in_new_session(analysis_id: str, status: str):
    """
    Função de emergência. Cria uma nova sessão de DB isolada
    apenas para atualizar o STATUS de uma análise (ex: para 'failed').
    Usado quando a sessão principal falha e sofre rollback.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    try:
        # Cria uma nova conexão/sessão
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
    """
    Função de emergência. Cria uma nova sessão de DB isolada
    apenas para salvar um ALERTA de erro crítico.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    try:
        # Cria uma nova conexão/sessão
        db_engine = create_engine("sqlite:///./db/database.db")
        SessionLocalNew = sessionmaker(bind=db_engine)
        session_new = SessionLocalNew()
        try:
            # Verifica se já existe um alerta de erro para não duplicar
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