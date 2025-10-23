import re
from collections import defaultdict
from db.models import Alert
from urllib.parse import unquote_plus

PORT_SCAN_THRESHOLD = 10 # Alerta se um IP tentar aceder a mais de 10 portas num único host

class RulesEngine:
    def __init__(self, analysis_id: str, custom_payload_rules: list = [], custom_port_rules: list = []):
        self.analysis_id = analysis_id
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        self.custom_port_tracker = set()
        self.custom_payload_tracker = set()
        
        self.custom_payload_rules = custom_payload_rules
        
        self.custom_port_rules_map = {}
        for rule in custom_port_rules:
            try:
                self.custom_port_rules_map[int(rule.value)] = rule
            except:
                pass 

    def process_packet(self, pkt) -> list[Alert]:
        alerts = []
        
        info = self._extract_packet_info(pkt)

        if info['dst_port'] in [80, 443, 8080] or info['src_port'] in [80, 443, 8080]:
            try:
                info['decoded_payload'] = unquote_plus(info['payload'].decode('utf-8', errors='ignore')).lower()
            except Exception:
                info['decoded_payload'] = info['payload'].decode('utf-8', errors='ignore').lower()
        else:
            info['decoded_payload'] = None

        alerts.extend(self._rule_detect_custom_port(info))
        alerts.extend(self._rule_detect_custom_payload(info))
        alerts.extend(self._rule_detect_port_scan(info, pkt))
        
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
    
    def _rule_detect_custom_port(self, info: dict) -> list[Alert]:
        alerts = []
        dst_port = info.get('dst_port')
        
        rule = self.custom_port_rules_map.get(dst_port)
        if not rule:
            return alerts
            
        tracker_key = (info['src_ip'], dst_port)
        if tracker_key not in self.custom_port_tracker:
            alerts.append(Alert(
                analysis_id=self.analysis_id, 
                alert_type=rule.alert_type,
                severity=rule.severity, 
                src_ip=info['src_ip'], 
                dst_ip=info['dst_ip'],
                port=dst_port, 
                protocol=info['proto'],
                evidence=f"Detetada conexão à porta customizada {dst_port} (Regra: {rule.name})"
            ))
            self.custom_port_tracker.add(tracker_key)
            
        return alerts

    def _rule_detect_custom_payload(self, info: dict) -> list[Alert]:
        alerts = []
        if not info['decoded_payload'] or not self.custom_payload_rules:
            return alerts
            
        for rule in self.custom_payload_rules:
            if rule.value.lower() in info['decoded_payload']:
                
                tracker_key = (info['src_ip'], info['dst_ip'], rule.id)
                if tracker_key not in self.custom_payload_tracker:
                    alerts.append(Alert(
                        analysis_id=self.analysis_id,
                        alert_type=rule.alert_type,
                        severity=rule.severity,
                        src_ip=info['src_ip'], dst_ip=info['dst_ip'],
                        port=info['dst_port'], protocol=info['proto'],
                        evidence=f"Detetada assinatura de payload customizado (Regra: {rule.name})"
                    ))
                    self.custom_payload_tracker.add(tracker_key)
        return alerts

    def _rule_detect_port_scan(self, info: dict, pkt) -> list[Alert]:
        alerts = []
        if info['proto'] != 'tcp' or not info['src_ip'] or not info['dst_ip']:
            return alerts
            
        is_syn_packet = False
        try:
            if pkt.tcp.flags_syn == '1' and pkt.tcp.flags_ack == '0':
                is_syn_packet = True
        except AttributeError:
            return alerts 

        if not is_syn_packet:
            return alerts
            
        tracker = self.port_scan_tracker[info['src_ip']][info['dst_ip']]
        
        if 'alerted' in tracker:
            return alerts
            
        tracker.add(info['dst_port'])
        
        if len(tracker) > PORT_SCAN_THRESHOLD:
            alerts.append(Alert(
                analysis_id=self.analysis_id, alert_type="port_scan_detected",
                severity="high", src_ip=info['src_ip'], dst_ip=info['dst_ip'],
                evidence=f"IP de origem {info['src_ip']} enviou pacotes SYN para {len(tracker)} portas no destino {info['dst_ip']}."
            ))
            tracker.add('alerted')
        return alerts