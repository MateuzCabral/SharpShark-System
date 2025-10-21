import os
import asyncio
import time
import pyshark
from sqlalchemy.orm import Session
from typing import Dict
from db.models import Analysis, Stream, Stat, IpRecord, File, Alert
from datetime import datetime, timezone
from core.config import UPLOAD_DIRECTORY
from analysis_rules import RulesEngine

UPLOAD_DIR = UPLOAD_DIRECTORY
STREAMS_DIR = os.path.join(UPLOAD_DIR, "streams")
os.makedirs(STREAMS_DIR, exist_ok=True)

def analyze_file(session: Session, file_obj: File, analysis_id: str) -> Analysis:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    
    start_time = time.perf_counter()
    pcap_path = file_obj.file_path

    analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise RuntimeError(f"Análise {analysis_id} não encontrada no início de analyze_file.")

    rules_engine = RulesEngine(analysis_id=analysis.id)

    protocol_counts: Dict[str, int] = {}
    port_counts: Dict[int, int] = {}
    ip_counts: Dict[str, int] = {}
    streams_map: Dict[str, Dict] = {} 
    total_packets = 0

    try:
        capture = pyshark.FileCapture(pcap_path, keep_packets=False, use_json=True, include_raw=True)
        
        for pkt in capture:
            total_packets += 1

            new_alerts = rules_engine.process_packet(pkt)
            if new_alerts:
                session.add_all(new_alerts)
            
            proto = next((lay.layer_name for lay in pkt.layers), "unknown")
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            src, dst = (pkt.ip.src, pkt.ip.dst) if hasattr(pkt, 'ip') else \
                       (pkt.ipv6.src, pkt.ipv6.dst) if hasattr(pkt, 'ipv6') else (None, None)
            
            if src: ip_counts[src] = ip_counts.get(src, 0) + 1
            if dst: ip_counts[dst] = ip_counts.get(dst, 0) + 1

            sport, dport = (int(pkt.tcp.srcport), int(pkt.tcp.dstport)) if hasattr(pkt, 'tcp') else \
                           (int(pkt.udp.srcport), int(pkt.udp.dstport)) if hasattr(pkt, 'udp') else (None, None)
            
            if sport: port_counts[sport] = port_counts.get(sport, 0) + 1
            if dport: port_counts[dport] = port_counts.get(dport, 0) + 1

            stream_key = f"tcp-{pkt.tcp.stream}" if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'stream') else \
                         f"{src}:{sport}-{dst}:{dport}" if all([src, dst, sport, dport]) else f"pkt-{total_packets}"

            if stream_key not in streams_map:
                streams_map[stream_key] = {"packets": [], "stream_number": len(streams_map) + 1}
            
            payload_bytes = bytes.fromhex(pkt.tcp.payload.replace(":", "")) if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload') else \
                            bytes.fromhex(pkt.udp.payload.replace(":", "")) if hasattr(pkt, 'udp') and hasattr(pkt.udp, 'payload') else b''

            streams_map[stream_key]["packets"].append({"payload": payload_bytes})

            if total_packets % 500 == 0:
                session.commit()

        capture.close()

    except Exception as e:
        analysis.status = "failed"
        fail_alert = Alert(analysis_id=analysis.id, alert_type="analysis_error", severity="critical", evidence=str(e)[:2000])
        session.add(fail_alert)
        session.commit()
        raise
    
    stream_count = 0
    for meta in streams_map.values():
        full_payload = b"".join(p["payload"] for p in meta["packets"] if p.get("payload"))
        if not full_payload:
            continue
        
        stream_count += 1
        stream_filename = f"{analysis.id}_stream_{stream_count}.bin"
        stream_path = os.path.join(STREAMS_DIR, stream_filename)
        with open(stream_path, "wb") as sf:
            sf.write(full_payload)
        
        preview = full_payload[:200].hex()
        session.add(Stream(
            analysis_id=analysis.id, stream_number=meta["stream_number"],
            content_path=stream_path, preview=preview
        ))

    for proto, cnt in protocol_counts.items():
        session.add(Stat(analysis_id=analysis.id, category="protocol", key=proto, count=cnt))
    for port, cnt in port_counts.items():
        session.add(Stat(analysis_id=analysis.id, category="port", key=str(port), count=cnt))
    for ip, cnt in ip_counts.items():
        session.add(IpRecord(analysis_id=analysis.id, ip=ip, role="unknown", count=cnt))

    end_time = time.perf_counter()
    analysis.status = "completed"
    analysis.total_packets = total_packets
    analysis.total_streams = stream_count
    analysis.duration = round(end_time - start_time, 3)
    analysis.analyzed_at = datetime.now(timezone.utc)
    
    session.commit()
    return analysis