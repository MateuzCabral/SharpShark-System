import re
from collections import defaultdict
from db.models import Alert
from urllib.parse import unquote_plus

PORT_SCAN_THRESHOLD = 10 # Alerta se um IP tentar aceder a mais de 10 portas num único host

class RulesEngine:
    def __init__(self, analysis_id: str):
        self.analysis_id = analysis_id
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))

    def process_packet(self, pkt) -> list[Alert]:
        alerts = []
        
        info = self._extract_packet_info(pkt)

        if info['dst_port'] in [80, 443, 8080]:
            try:
                info['decoded_payload'] = unquote_plus(info['payload'].decode('utf-8', errors='ignore'))
            except Exception:
                info['decoded_payload'] = info['payload'].decode('utf-8', errors='ignore')
        else:
            info['decoded_payload'] = None

        alerts.extend(self._rule_suspicious_ports(info))
        alerts.extend(self._rule_detect_port_scan(info))
        alerts.extend(self._rule_detect_shellshock(info))
        alerts.extend(self._rule_detect_sqli(info))
        alerts.extend(self._rule_detect_xss(info))
        
        return alerts

    def _extract_packet_info(self, pkt) -> dict:
        info = {
            "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None,
            "proto": next((lay.layer_name for lay in pkt.layers), "unknown"),
            "payload": b""
        }
        if hasattr(pkt, 'ip'):
            info['src_ip'] = pkt.ip.src
            info['dst_ip'] = pkt.ip.dst
        elif hasattr(pkt, 'ipv6'):
            info['src_ip'] = pkt.ipv6.src
            info['dst_ip'] = pkt.ipv6.dst
            
        if hasattr(pkt, 'tcp'):
            info['src_port'] = int(pkt.tcp.srcport)
            info['dst_port'] = int(pkt.tcp.dstport)
            if hasattr(pkt.tcp, 'payload'):
                info['payload'] = bytes.fromhex(pkt.tcp.payload.replace(":", ""))
        elif hasattr(pkt, 'udp'):
            info['src_port'] = int(pkt.udp.srcport)
            info['dst_port'] = int(pkt.udp.dstport)
            if hasattr(pkt.udp, 'payload'):
                info['payload'] = bytes.fromhex(pkt.udp.payload.replace(":", ""))

        return info

    # --- REGRA 1: Portas Suspeitas ---
    def _rule_suspicious_ports(self, info: dict) -> list[Alert]:
        alerts = []
        port_map = {
            21: "FTP", 
            23: "Telnet", 
            3389: "RDP",
            22: "SSH" 
        }
        
        if info['dst_port'] in port_map:
            alerts.append(Alert(
                analysis_id=self.analysis_id, alert_type="suspicious_protocol_use",
                severity="high", src_ip=info['src_ip'], dst_ip=info['dst_ip'],
                port=info['dst_port'], protocol=info['proto'],
                evidence=f"Uso de protocolo potencialmente inseguro ou não monitorizado detetado: {port_map[info['dst_port']]}"
            ))
        return alerts

    # --- REGRA 2: Deteção de Port Scan (Threshold) ---
    def _rule_detect_port_scan(self, info: dict) -> list[Alert]:
        alerts = []
        if info['proto'] != 'tcp' or not info['src_ip'] or not info['dst_ip']:
            return alerts
            
        tracker = self.port_scan_tracker[info['src_ip']][info['dst_ip']]
        
        if 'alerted' in tracker:
            return alerts
            
        tracker.add(info['dst_port'])
        
        if len(tracker) > PORT_SCAN_THRESHOLD:
            alerts.append(Alert(
                analysis_id=self.analysis_id, alert_type="port_scan_detected",
                severity="high", src_ip=info['src_ip'], dst_ip=info['dst_ip'],
                evidence=f"IP de origem {info['src_ip']} tentou aceder a {len(tracker)} portas no destino {info['dst_ip']}."
            ))
            tracker.add('alerted') # Marca para não alertar novamente
        return alerts

    # --- REGRA 3: Deteção de SQL Injection (Assinatura com Regex) ---
    def _rule_detect_sqli(self, info: dict) -> list[Alert]:
        alerts = []
        if not info['decoded_payload']:
            return alerts

        # Padrões Regex para SQLi comuns (case-insensitive)
        sqli_patterns = [
            r"(\s*')\s*OR\s*(\d+)\s*=\s*(\d+)", # ' OR 1=1
            r"\bUNION\s+SELECT\b",
            r"(\s*--)|(\s*/\*.*\*/)" # Comentários SQL
        ]
        
        for pattern in sqli_patterns:
            if re.search(pattern, info['decoded_payload'], re.IGNORECASE):
                alerts.append(Alert(
                    analysis_id=self.analysis_id, alert_type="sql_injection_attempt",
                    severity="critical", src_ip=info['src_ip'], dst_ip=info['dst_ip'],
                    port=info['dst_port'], protocol=info['proto'],
                    evidence="Detetada possível tentativa de SQL Injection no payload HTTP."
                ))
                return alerts # Retorna no primeiro match
        return alerts

    # --- REGRA 4: Deteção de Cross-Site Scripting (XSS) ---
    def _rule_detect_xss(self, info: dict) -> list[Alert]:
        alerts = []
        if not info['decoded_payload']:
            return alerts

        # Padrões Regex para XSS comuns (case-insensitive)
        xss_patterns = [
            r"<script.*?>.*?</script>",
            r"\balert\s*\(",
            r"\bonerror\s*=",
            r"\bonload\s*=",
            r"javascript:"
        ]

        for pattern in xss_patterns:
            if re.search(pattern, info['decoded_payload'], re.IGNORECASE):
                alerts.append(Alert(
                    analysis_id=self.analysis_id, alert_type="xss_attempt",
                    severity="high", src_ip=info['src_ip'], dst_ip=info['dst_ip'],
                    port=info['dst_port'], protocol=info['proto'],
                    evidence="Detetada possível tentativa de Cross-Site Scripting (XSS) no payload HTTP."
                ))
                return alerts # Retorna no primeiro match
        return alerts
