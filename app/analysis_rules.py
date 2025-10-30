# app/analysis_rules.py
import re
from collections import defaultdict
from db.models import Alert
from urllib.parse import unquote_plus # Para decodificar URLs
import logging

# Limites para detecção de regras
PORT_SCAN_THRESHOLD = 10     # Nº de portas diferentes (SYN) para disparar alerta de Port Scan
BRUTE_FORCE_THRESHOLD = 10 # Nº de falhas de login para disparar alerta de Brute Force

logger = logging.getLogger("sharpshark.rules_engine")

class RulesEngine:
    """
    Motor de regras de detecção.
    Esta classe é instanciada para *cada* análise e mantém o estado
    (trackers) durante o processamento dos pacotes.
    """
    def __init__(self, analysis_id: str, custom_payload_rules: list = [], custom_port_rules: list = []):
        self.analysis_id = analysis_id
        
        # --- Trackers de Estado (para evitar alertas duplicados) ---
        self.custom_port_tracker = set()
        # ESTE TRACKER É COMPARTILHADO ENTRE PACOTE E STREAM
        self.custom_payload_tracker = set()
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        self.bruteforce_tracker = defaultdict(int)
        self.bruteforce_alerted = set()
        
        # --- Regras Customizadas ---
        self.custom_payload_rules = custom_payload_rules
        self.custom_port_rules_map = {}
        for rule in custom_port_rules:
            try:
                self.custom_port_rules_map[int(rule.value)] = rule
            except:
                pass # Ignora regras de porta malformadas (valor não-int)

    # --- INÍCIO DA ALTERAÇÃO: MÉTODO 'process_stream' ATUALIZADO ---

    def process_stream(self, full_payload: bytes, stream_meta: dict) -> list[Alert]:
        """
        Regra: Detecta uma string/assinatura customizada no PAYLOAD COMPLETO DO STREAM.
        Recebe 'stream_meta' contendo IPs/Portas do primeiro pacote.
        """
        alerts = []
        if not full_payload or not self.custom_payload_rules:
            return alerts

        # Tenta decodificar o payload completo
        try:
            decoded_payload = full_payload.decode('utf-8', errors='ignore').lower()
        except Exception:
            return alerts # Não é um payload decodificável

        # Extrai info dos metadados do stream (armazenados do primeiro pacote)
        src_ip = stream_meta.get("src_ip")
        dst_ip = stream_meta.get("dst_ip")
        dst_port = stream_meta.get("dst_port")
        # Pega o protocolo original (ex: TCP) e formata
        proto_original = stream_meta.get("proto", "N/A")
        proto_display = f"Stream ({proto_original})" # Sua sugestão! Ex: "Stream (TCP)"

        for rule in self.custom_payload_rules:
            try:
                if rule.value.lower() in decoded_payload:
                    # A chave do tracker (src_ip, dst_ip, rule.id) é a mesma
                    # usada na verificação por pacote.
                    tracker_key = (src_ip, dst_ip, rule.id)

                    # *** ESTA É A CORREÇÃO DE DUPLICIDADE ***
                    # Se a análise por PACOTE (em _rule_detect_custom_payload)
                    # já encontrou essa regra para este fluxo, não adiciona de novo.
                    if tracker_key not in self.custom_payload_tracker:
                        alerts.append(Alert(
                            analysis_id=self.analysis_id, 
                            alert_type=rule.alert_type, 
                            severity=rule.severity,
                            src_ip=src_ip,     # <-- Corrigido
                            dst_ip=dst_ip,     # <-- Corrigido
                            port=dst_port,   # <-- Corrigido
                            protocol=proto_display, # <-- Corrigido
                            evidence=f"Assinatura de stream (Regra: {rule.name}) encontrada: '{rule.value}'"
                        ))
                        # Adiciona ao tracker para evitar duplicatas
                        self.custom_payload_tracker.add(tracker_key)
            except Exception as e_rule:
                logger.warning(f"Análise {self.analysis_id}: Erro ao processar regra de stream '{rule.name}': {e_rule}")
        
        return alerts

    # --- FIM DA ALTERAÇÃO ---

    def process_packet(self, pkt) -> list[Alert]:
        """
        Ponto de entrada principal. Processa um único pacote
        e retorna uma lista de novos Alertas (se houver).
        """
        alerts = []
        
        # 1. Normaliza as informações do pacote
        info = self._extract_packet_info(pkt)

        # 2. Tenta decodificar o payload
        if info['payload']:
            try:
                if info.get('dst_port') in [80, 443, 8080] or info.get('src_port') in [80, 443, 8080]:
                    info['decoded_payload'] = unquote_plus(info['payload'].decode('utf-8', errors='ignore')).lower()
                else:
                    info['decoded_payload'] = info['payload'].decode('utf-8', errors='ignore').lower()
            except Exception:
                info['decoded_payload'] = None
        else:
            info['decoded_payload'] = None

        # 3. Executa todas as regras
        alerts.extend(self._rule_detect_custom_port(info))
        alerts.extend(self._rule_detect_custom_payload(info))
        alerts.extend(self._rule_detect_port_scan(info, pkt))
        alerts.extend(self._rule_detect_bruteforce(info))

        return alerts

    def _extract_packet_info(self, pkt) -> dict:
        """
        Helper para extrair e normalizar dados do objeto PyShark 'pkt'
        em um dicionário simples.
        """
        info = {
            "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None,
            "proto": "UNKNOWN",
            "payload": b"",
            "decoded_payload": None
        }

        if hasattr(pkt, 'ip'):
            info['src_ip'] = pkt.ip.src
            info['dst_ip'] = pkt.ip.dst
        elif hasattr(pkt, 'ipv6'):
            info['src_ip'] = pkt.ipv6.src
            info['dst_ip'] = pkt.ipv6.dst

        transport_layer = None
        if hasattr(pkt, 'tcp'):
            transport_layer = pkt.tcp
            info['src_port'] = int(transport_layer.srcport)
            info['dst_port'] = int(transport_layer.dstport)
        elif hasattr(pkt, 'udp'):
            transport_layer = pkt.udp
            info['src_port'] = int(transport_layer.srcport)
            info['dst_port'] = int(transport_layer.dstport)

        if transport_layer and hasattr(transport_layer, 'payload'):
            try:
                if isinstance(transport_layer.payload, list):
                    payload_hex = "".join(transport_layer.payload).replace(":", "")
                else:
                    payload_hex = str(transport_layer.payload).replace(":", "")
                info['payload'] = bytes.fromhex(payload_hex)
            except (ValueError, TypeError) as e:
                info['payload'] = b""

        proto = pkt.highest_layer
        if not proto or str(proto).lower() == 'data':
            if hasattr(pkt, 'tcp'): proto = 'TCP'
            elif hasattr(pkt, 'udp'): proto = 'UDP'
            elif hasattr(pkt, 'arp'): proto = 'ARP'
            elif hasattr(pkt, 'icmp'): proto = 'ICMP'
            elif hasattr(pkt, 'ip'): proto = 'IP'
            else: proto = next((lay.layer_name for lay in pkt.layers), "UNKNOWN")

        proto_str = str(proto).upper().replace('_RAW', '')
        info['proto'] = proto_str

        return info

    def _rule_detect_custom_port(self, info: dict) -> list[Alert]:
        alerts = []
        dst_port = info.get('dst_port')
        
        rule = self.custom_port_rules_map.get(dst_port)
        if not rule: return alerts
        
        tracker_key = (info['src_ip'], dst_port)
        if tracker_key not in self.custom_port_tracker:
            alerts.append(Alert(
                analysis_id=self.analysis_id, alert_type=rule.alert_type, severity=rule.severity,
                src_ip=info['src_ip'], dst_ip=info['dst_ip'], port=dst_port,
                protocol=info['proto'],
                evidence=f"Detetada conexão à porta customizada {dst_port} (Regra: {rule.name})"
            ))
            self.custom_port_tracker.add(tracker_key)
        return alerts

    def _rule_detect_custom_payload(self, info: dict) -> list[Alert]:
        """ Regra: Detecta uma string/assinatura customizada no payload POR PACOTE. """
        alerts = []
        if not info['decoded_payload'] or not self.custom_payload_rules: return alerts
        
        for rule in self.custom_payload_rules:
            if rule.value.lower() in info['decoded_payload']:
                tracker_key = (info['src_ip'], info['dst_ip'], rule.id)
                if tracker_key not in self.custom_payload_tracker:
                    alerts.append(Alert(
                        analysis_id=self.analysis_id, alert_type=rule.alert_type, severity=rule.severity,
                        src_ip=info['src_ip'], dst_ip=info['dst_ip'], port=info.get('dst_port'),
                        protocol=info['proto'], # Protocolo original do pacote
                        evidence=f"Assinatura de payload (por pacote) (Regra: {rule.name})"
                    ))
                    self.custom_payload_tracker.add(tracker_key)
        return alerts

    def _rule_detect_port_scan(self, info: dict, pkt) -> list[Alert]:
        alerts = []
        if info['proto'] != 'TCP' or not info['src_ip'] or not info['dst_ip']: return alerts
        
        is_syn_packet = False
        try:
            if pkt.tcp.flags_syn == '1' and pkt.tcp.flags_ack == '0': is_syn_packet = True
        except AttributeError: return alerts
        
        if not is_syn_packet: return alerts

        tracker = self.port_scan_tracker[info['src_ip']][info['dst_ip']]
        
        if 'alerted' in tracker: return alerts
        
        tracker.add(info['dst_port'])
        
        if len(tracker) > PORT_SCAN_THRESHOLD:
            alerts.append(Alert(
                analysis_id=self.analysis_id, alert_type="port_scan_detected", severity="high",
                src_ip=info['src_ip'], dst_ip=info['dst_ip'],
                protocol=info['proto'],
                evidence=f"IP de origem {info['src_ip']} enviou pacotes SYN para {len(tracker)} portas no destino {info['dst_ip']}."
            ))
            tracker.add('alerted')
        return alerts

    def _rule_detect_bruteforce(self, info: dict) -> list[Alert]:
        alerts = []
        if not info['decoded_payload']: return alerts

        failure_signatures = ["530 login incorrect", "http/1.1 401 unauthorized", "authentication failed"]
        
        is_failure = any(sig in info['decoded_payload'] for sig in failure_signatures)
        if not is_failure: return alerts
        
        attacker_ip = info.get('dst_ip')
        victim_ip = info.get('src_ip')
        victim_port = info.get('src_port')

        if not all([attacker_ip, victim_ip, victim_port]): return alerts
        
        tracker_key = (attacker_ip, victim_ip, victim_port)
        
        if tracker_key in self.bruteforce_alerted: return alerts
        
        self.bruteforce_tracker[tracker_key] += 1
        
        if self.bruteforce_tracker[tracker_key] > BRUTE_FORCE_THRESHOLD:
            alerts.append(Alert(
                analysis_id=self.analysis_id, alert_type="brute_force_detected", severity="critical",
                src_ip=attacker_ip, dst_ip=victim_ip, port=victim_port,
                protocol=info['proto'],
                evidence=f"Detetadas {self.bruteforce_tracker[tracker_key]} tentativas de login falhadas de {attacker_ip} para {victim_ip}:{victim_port}"
            ))
            self.bruteforce_alerted.add(tracker_key)
        return alerts