import time
import logging
from collections import defaultdict

logger = logging.getLogger("ThreatRadar.AnomalyDetector")


class AnomalyDetector:
    """
    Модуль обнаружения сетевых аномалий.
    Анализирует входящий поток пакетов и выявляет подозрительную активность:
    - Сканирование портов (Port Scanning)
    - SYN-флуд (SYN Flood)
    """

    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback

        self.PORT_SCAN_THRESHOLD = 15
        self.SYN_FLOOD_THRESHOLD = 50
        self.TIME_WINDOW = 5.0

        self.syn_counts = defaultdict(list)
        self.port_scans = defaultdict(set)
        self.first_seen = {}

    def analyze(self, packet_info):
        """Основной метод анализа пакета."""
        if not packet_info or packet_info["protocol"] != "TCP":
            return

        src_ip = packet_info["src_ip"]
        dst_ip = packet_info["dst_ip"]
        dst_port = packet_info["dst_port"]
        flags = packet_info.get("tcp_flags", "")
        current_time = packet_info["timestamp"]

        self._clean_old_records(current_time)

        if flags and 'S' in str(flags):
            self._check_syn_flood(src_ip, dst_ip, current_time)

        if dst_port is not None:
            self._check_port_scan(src_ip, dst_ip, dst_port, current_time)

    def _check_syn_flood(self, src_ip, dst_ip, current_time):
        """Логика выявления DoS-атаки типа SYN Flood."""
        self.syn_counts[src_ip].append(current_time)

        if len(self.syn_counts[src_ip]) > self.SYN_FLOOD_THRESHOLD:
            self._trigger_alert(
                severity="CRITICAL",
                threat_type="SYN Flood",
                src_ip=src_ip,
                dst_ip=dst_ip,
                message=f"Обнаружен SYN-флуд: >{self.SYN_FLOOD_THRESHOLD} пакетов за {self.TIME_WINDOW}с"
            )
            self.syn_counts[src_ip].clear()

    def _check_port_scan(self, src_ip, dst_ip, dst_port, current_time):
        """Логика выявления агрессивного сканирования портов."""
        if src_ip not in self.first_seen:
            self.first_seen[src_ip] = current_time

        if current_time - self.first_seen[src_ip] > self.TIME_WINDOW:
            self.port_scans[src_ip].clear()
            self.first_seen[src_ip] = current_time

        self.port_scans[src_ip].add(dst_port)

        if len(self.port_scans[src_ip]) > self.PORT_SCAN_THRESHOLD:
            self._trigger_alert(
                severity="HIGH",
                threat_type="Port Scan",
                src_ip=src_ip,
                dst_ip=dst_ip,
                message=f"Сканирование портов: обнаружено обращение к {len(self.port_scans[src_ip])} уникальным портам"
            )
            self.port_scans[src_ip].clear()
            self.first_seen[src_ip] = current_time

    def _trigger_alert(self, severity, threat_type, src_ip, dst_ip, message):
        """Формирование и отправка оповещения об угрозе."""
        alert_data = {
            "timestamp": time.time(),
            "severity": severity,
            "type": threat_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "message": message
        }
        logger.warning(f"УГРОЗА [{severity}] {threat_type} от {src_ip}: {message}")

        if self.alert_callback:
            self.alert_callback(alert_data)

    def _clean_old_records(self, current_time):
        """Удаление устаревших данных для предотвращения переполнения памяти."""
        for ip in list(self.syn_counts.keys()):
            self.syn_counts[ip] = [t for t in self.syn_counts[ip] if current_time - t <= self.TIME_WINDOW]
            if not self.syn_counts[ip]:
                del self.syn_counts[ip]

        for ip in list(self.first_seen.keys()):
            if current_time - self.first_seen[ip] > self.TIME_WINDOW * 2:
                if ip in self.port_scans:
                    del self.port_scans[ip]
                del self.first_seen[ip]