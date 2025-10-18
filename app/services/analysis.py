import os
import asyncio
import traceback
from sqlalchemy.orm import Session
from typing import Dict, Tuple
from db.models import Analysis, Stream, Alert, Stat, IpRecord, File
from datetime import datetime, timezone
import pyshark
import time

UPLOAD_DIR = "./uploads"
STREAMS_DIR = os.path.join(UPLOAD_DIR, "streams")
os.makedirs(STREAMS_DIR, exist_ok=True)


SUSPICIOUS_PAYLOAD_KEYWORDS = [b"password", b"passwd", b"login", b"admin", b"root", b"php"]
SUSPICIOUS_PORTS = {23: "telnet", 21: "ftp", 3389: "rdp", 22: "ssh (check if unexpected)"}

def analyze_file(session: Session, file_obj: File, analysis_id: str | None = None) -> Analysis:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    
    start_time = time.perf_counter()

    pcap_path = file_obj.file_path

    if analysis_id:
        analysis = session.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            analysis = Analysis(file_id=file_obj.id, user_id=file_obj.user_id, status="in_progress")
            session.add(analysis)
            session.commit()
            session.refresh(analysis)
        else:
            analysis.status = "in_progress"
            session.add(analysis)
            session.commit()
    else:
        analysis = Analysis(file_id=file_obj.id, user_id=file_obj.user_id, status="in_progress")
        session.add(analysis)
        session.commit()
        session.refresh(analysis)

    protocol_counts: Dict[str, int] = {}
    port_counts: Dict[int, int] = {}
    ip_counts: Dict[str, int] = {}
    streams_map: Dict[str, Dict] = {}  

    total_packets = 0

    try:
        
        capture = pyshark.FileCapture(pcap_path, keep_packets=False, decode_as={})
        for pkt in capture:
            total_packets += 1

            proto = next((lay.layer_name for lay in pkt.layers), "unknown")
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            try:
                if hasattr(pkt, "ip"):
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    ip_counts[src] = ip_counts.get(src, 0) + 1
                    ip_counts[dst] = ip_counts.get(dst, 0) + 1
                elif hasattr(pkt, "ipv6"):
                    src = pkt.ipv6.src
                    dst = pkt.ipv6.dst
                    ip_counts[src] = ip_counts.get(src, 0) + 1
                    ip_counts[dst] = ip_counts.get(dst, 0) + 1
                else:
                    src = dst = None
            except Exception:
                src = dst = None

            sport = None
            dport = None
            try:
                if hasattr(pkt, "tcp"):
                    sport = int(pkt.tcp.srcport)
                    dport = int(pkt.tcp.dstport)
                    port_counts[sport] = port_counts.get(sport, 0) + 1
                    port_counts[dport] = port_counts.get(dport, 0) + 1
                elif hasattr(pkt, "udp"):
                    sport = int(pkt.udp.srcport)
                    dport = int(pkt.udp.dstport)
                    port_counts[sport] = port_counts.get(sport, 0) + 1
                    port_counts[dport] = port_counts.get(dport, 0) + 1
            except Exception:
                pass

            stream_key = None
            try:
                if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "stream"):
                    stream_key = f"tcp-{pkt.tcp.stream}"
                else:
                    if src and dst and sport is not None and dport is not None:
                        stream_key = f"{src}:{sport}-{dst}:{dport}"
                    else:
                        stream_key = f"pkt-{total_packets}"
            except Exception:
                stream_key = f"pkt-{total_packets}"

            meta = streams_map.get(stream_key)
            if not meta:
                streams_map[stream_key] = {"packets": [], "stream_number": len(streams_map) + 1}
                meta = streams_map[stream_key]

            payload_bytes = b""
            try:
                if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
                    payload_hex = getattr(pkt.tcp, "payload").replace(":", "")
                    payload_bytes = bytes.fromhex(payload_hex) if payload_hex else b""
                else:
                    for layer in pkt.layers:
                        if hasattr(layer, "get_field_by_showname"):
                            pass
                    try:
                        rb = pkt.get_raw_packet()
                        if rb:
                            payload_bytes = rb
                    except Exception:
                        pass
            except Exception:
                payload_bytes = b""

            meta["packets"].append({
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "proto": proto,
                "payload": payload_bytes[:512]
            })

            if dport in SUSPICIOUS_PORTS:
                alert = Alert(
                    analysis_id=analysis.id,
                    alert_type="suspicious_port",
                    severity="high",
                    src_ip=src or "",
                    dst_ip=dst or "",
                    port=dport,
                    protocol=proto,
                    evidence=f"Port {dport} ({SUSPICIOUS_PORTS[dport]}) observed"
                )
                session.add(alert)
            try:
                if payload_bytes:
                    low = payload_bytes.lower()
                    for kw in SUSPICIOUS_PAYLOAD_KEYWORDS:
                        if kw in low:
                            alert = Alert(
                                analysis_id=analysis.id,
                                alert_type="suspicious_payload",
                                severity="medium",
                                src_ip=src or "",
                                dst_ip=dst or "",
                                port=dport,
                                protocol=proto,
                                evidence=f"Payload contains suspicious keyword: {kw.decode(errors='ignore')}"
                            )
                            session.add(alert)
                            break
            except Exception:
                pass

            if total_packets % 500 == 0:
                session.commit()

        try:
            capture.close()
        except Exception:
            pass

        if total_packets == 0:
            raise RuntimeError("Nenhum pacote foi capturado, possivelmente arquivo inválido ou vazio.")

        stream_count = 0
        for key, meta in streams_map.items():
            packets = meta["packets"]
            if not packets:
                continue  

            if not any(pkt["payload"] for pkt in packets):
                continue

            stream_count += 1
            stream_filename = f"{analysis.id}_stream_{stream_count}.bin"
            stream_path = os.path.join(STREAMS_DIR, stream_filename)
            with open(stream_path, "wb") as sf:
                for pktmeta in packets:
                    payload = pktmeta.get("payload")
                    if payload:
                        sf.write(payload)

            if os.path.getsize(stream_path) == 0:
                os.remove(stream_path)
                continue

            preview = ""
            try:
                with open(stream_path, "rb") as sf:
                    first = sf.read(200)
                    preview = first.hex() if first else ""
            except Exception:
                preview = ""

            stream_model = Stream(
                analysis_id=analysis.id,
                stream_number=meta.get("stream_number", stream_count),
                content_path=stream_path,
                preview=preview
            )
            session.add(stream_model)

        for proto, cnt in protocol_counts.items():
            session.add(Stat(analysis_id=analysis.id, category="protocol", key=proto, count=cnt))

        for port, cnt in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:50]:
            session.add(Stat(analysis_id=analysis.id, category="port", key=str(port), count=cnt))

        for ip, cnt in ip_counts.items():
            session.add(IpRecord(
                analysis_id=analysis.id,
                ip=ip,
                role="unknown",
                count=cnt,
                hostname="unknown",
                city="unknown",
                region="unknown",
                country="unknown",
                organization="unknown"
            ))

        end_time = time.perf_counter()
       
        analysis.status = "completed"
        analysis.total_packets = total_packets
        analysis.total_streams = stream_count
        analysis.duration = round(end_time - start_time, 3)
        analysis.analyzed_at = datetime.now(tz=timezone.utc)

        session.commit()
        session.refresh(analysis)
        return analysis

    except Exception as e:
        tb = traceback.format_exc()
        try:
            analysis.status = "failed"
            session.add(analysis)
            session.commit()
        except Exception:
            pass

        try:
            for f in os.listdir(STREAMS_DIR):
                path = os.path.join(STREAMS_DIR, f)
                if os.path.isfile(path) and os.path.getsize(path) == 0:
                    os.remove(path)
        except Exception:
            pass

        fail_alert = Alert(
            analysis_id=analysis.id,
            alert_type="analysis_error",
            severity="critical",
            evidence=str(e)[:2000]
        )
        session.add(fail_alert)
        session.commit()
        raise
