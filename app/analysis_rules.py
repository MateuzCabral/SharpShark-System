import re
from collections import defaultdict
from db.models import Alert
from urllib.parse import unquote_plus # Para decodificar URLs

# Limites para detecção de regras
PORT_SCAN_THRESHOLD = 10     # Nº de portas diferentes (SYN) para disparar alerta de Port Scan
BRUTE_FORCE_THRESHOLD = 10 # Nº de falhas de login para disparar alerta de Brute Force

class RulesEngine:
    """
    Motor de regras de detecção.
    Esta classe é instanciada para *cada* análise e mantém o estado
    (trackers) durante o processamento dos pacotes.
    """
    def __init__(self, analysis_id: str, custom_payload_rules: list = [], custom_port_rules: list = []):
        self.analysis_id = analysis_id
        
        # --- Trackers de Estado (para evitar alertas duplicados) ---
        # Guarda (src_ip, dst_port) para regras de porta
        self.custom_port_tracker = set()
        # Guarda (src_ip, dst_ip, rule.id) para regras de payload
        self.custom_payload_tracker = set()
        # Guarda {src_ip: {dst_ip: set(portas)}} para Port Scan
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        # Guarda {(attacker_ip, victim_ip, victim_port): count} para Brute Force
        self.bruteforce_tracker = defaultdict(int)
        # Guarda (attacker_ip, victim_ip, victim_port) que já geraram alerta de Brute Force
        self.bruteforce_alerted = set()
        
        # --- Regras Customizadas ---
        self.custom_payload_rules = custom_payload_rules
        # Converte a lista de regras de porta em um mapa (dicionário)
        # para busca rápida (O(1) lookup)
        self.custom_port_rules_map = {}
        for rule in custom_port_rules:
            try:
                self.custom_port_rules_map[int(rule.value)] = rule
            except:
                pass # Ignora regras de porta malformadas (valor não-int)

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
                # Se for tráfego web, decodifica URL (ex: %20 -> ' ')
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

        # Extrai IPs (IPv4 ou IPv6)
        if hasattr(pkt, 'ip'):
            info['src_ip'] = pkt.ip.src
            info['dst_ip'] = pkt.ip.dst
        elif hasattr(pkt, 'ipv6'):
            info['src_ip'] = pkt.ipv6.src
            info['dst_ip'] = pkt.ipv6.dst

        # Extrai Portas (TCP ou UDP)
        transport_layer = None
        if hasattr(pkt, 'tcp'):
            transport_layer = pkt.tcp
            info['src_port'] = int(transport_layer.srcport)
            info['dst_port'] = int(transport_layer.dstport)
        elif hasattr(pkt, 'udp'):
            transport_layer = pkt.udp
            info['src_port'] = int(transport_layer.srcport)
            info['dst_port'] = int(transport_layer.dstport)

        # Extrai Payload (TCP ou UDP)
        if transport_layer and hasattr(transport_layer, 'payload'):
            try:
                # O payload do PyShark às vezes vem como lista, às vezes como string
                if isinstance(transport_layer.payload, list):
                     payload_hex = "".join(transport_layer.payload).replace(":", "")
                else:
                     payload_hex = str(transport_layer.payload).replace(":", "")
                info['payload'] = bytes.fromhex(payload_hex)
            except (ValueError, TypeError) as e:
                info['payload'] = b"" # Ignora payload malformado

        # Extrai Protocolo (Camada mais alta)
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
        """ Regra: Detecta conexão a uma porta customizada (definida pelo usuário). """
        alerts = []
        dst_port = info.get('dst_port')
        
        # Busca O(1) no mapa de regras de porta
        rule = self.custom_port_rules_map.get(dst_port)
        if not rule: return alerts # Nenhuma regra para esta porta
        
        # Gera alerta apenas *uma vez* por (IP de origem, Porta de destino)
        tracker_key = (info['src_ip'], dst_port)
        if tracker_key not in self.custom_port_tracker:
            alerts.append(Alert(
                analysis_id=self.analysis_id, alert_type=rule.alert_type, severity=rule.severity,
                src_ip=info['src_ip'], dst_ip=info['dst_ip'], port=dst_port,
                protocol=info['proto'],
                evidence=f"Detetada conexão à porta customizada {dst_port} (Regra: {rule.name})"
            ))
            self.custom_port_tracker.add(tracker_key) # Marca como alertado
        return alerts

    def _rule_detect_custom_payload(self, info: dict) -> list[Alert]:
        """ Regra: Detecta uma string/assinatura customizada no payload. """
        alerts = []
        if not info['decoded_payload'] or not self.custom_payload_rules: return alerts
        
        # Itera sobre todas as regras de payload (pode ser lento se houver muitas)
        for rule in self.custom_payload_rules:
            if rule.value.lower() in info['decoded_payload']:
                # Gera alerta apenas *uma vez* por (Origem, Destino, ID da Regra)
                tracker_key = (info['src_ip'], info['dst_ip'], rule.id)
                if tracker_key not in self.custom_payload_tracker:
                    alerts.append(Alert(
                        analysis_id=self.analysis_id, alert_type=rule.alert_type, severity=rule.severity,
                        src_ip=info['src_ip'], dst_ip=info['dst_ip'], port=info.get('dst_port'),
                        protocol=info['proto'],
                        evidence=f"Detetada assinatura de payload customizado (Regra: {rule.name})"
                    ))
                    self.custom_payload_tracker.add(tracker_key) # Marca como alertado
        return alerts

    def _rule_detect_port_scan(self, info: dict, pkt) -> list[Alert]:
        """ Regra: Detecta Port Scan (baseado em múltiplos pacotes SYN). """
        alerts = []
        # Só nos interessa pacotes TCP
        if info['proto'] != 'TCP' or not info['src_ip'] or not info['dst_ip']: return alerts
        
        # Verifica se é um pacote SYN (SYN=1, ACK=0)
        is_syn_packet = False
        try:
            if pkt.tcp.flags_syn == '1' and pkt.tcp.flags_ack == '0': is_syn_packet = True
        except AttributeError: return alerts # Pacote sem flags
        
        if not is_syn_packet: return alerts

        # Pega o 'set' de portas já vistas para este par (Origem, Destino)
        tracker = self.port_scan_tracker[info['src_ip']][info['dst_ip']]
        
        # Se já alertamos para este par, ignora
        if 'alerted' in tracker: return alerts
        
        # Adiciona a nova porta de destino ao set
        tracker.add(info['dst_port'])
        
        # Se o número de portas únicas ultrapassar o limite...
        if len(tracker) > PORT_SCAN_THRESHOLD:
            alerts.append(Alert(
                analysis_id=self.analysis_id, alert_type="port_scan_detected", severity="high",
                src_ip=info['src_ip'], dst_ip=info['dst_ip'],
                protocol=info['proto'],
                evidence=f"IP de origem {info['src_ip']} enviou pacotes SYN para {len(tracker)} portas no destino {info['dst_ip']}."
            ))
            tracker.add('alerted') # Marca como alertado para não repetir
        return alerts

    def _rule_detect_bruteforce(self, info: dict) -> list[Alert]:
        """ Regra: Detecta Brute Force (baseado em N falhas de login). """
        alerts = []
        if not info['decoded_payload']: return alerts

        # Assinaturas de falha de login (respostas do servidor)
        failure_signatures = ["530 login incorrect", "http/1.1 401 unauthorized", "authentication failed"]
        
        # Verifica se o payload (resposta) contém uma assinatura de falha
        is_failure = any(sig in info['decoded_payload'] for sig in failure_signatures)
        if not is_failure: return alerts
        
        # Inverte a lógica: a *origem* da falha é a vítima (servidor)
        attacker_ip = info.get('dst_ip') # O destino do pacote de resposta (cliente)
        victim_ip = info.get('src_ip')   # A origem do pacote de resposta (servidor)
        victim_port = info.get('src_port') # A porta do serviço (ex: 21, 80, 22)

        if not all([attacker_ip, victim_ip, victim_port]): return alerts
        
        tracker_key = (attacker_ip, victim_ip, victim_port)
        
        # Se já alertamos, ignora
        if tracker_key in self.bruteforce_alerted: return alerts
        
        # Incrementa o contador de falhas
        self.bruteforce_tracker[tracker_key] += 1
        
        # Se ultrapassar o limite...
        if self.bruteforce_tracker[tracker_key] > BRUTE_FORCE_THRESHOLD:
            alerts.append(Alert(
                analysis_id=self.analysis_id, alert_type="brute_force_detected", severity="critical",
                src_ip=attacker_ip, dst_ip=victim_ip, port=victim_port,
                protocol=info['proto'],
                evidence=f"Detetadas {self.bruteforce_tracker[tracker_key]} tentativas de login falhadas de {attacker_ip} para {victim_ip}:{victim_port}"
            ))
            self.bruteforce_alerted.add(tracker_key) # Marca como alertado
        return alerts