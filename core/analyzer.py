import json
import os
from collections import Counter

class TrafficAnalyzer:
    """
    Модуль для анализа накопленных данных о трафике.
    Группирует данные по IP, портам и протоколам, рассчитывает статистику.
    """

    def __init__(self, log_file):
        self.log_file = log_file

    def get_stats(self):
        """Считывает JSON и возвращает агрегированную статистику."""
        if not os.path.exists(self.log_file):
            return None

        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return None

        if not data:
            return None

        stats = {
            "total_packets": len(data),
            "top_sources": Counter([p["src_ip"] for p in data]).most_common(5),
            "top_destinations": Counter([p["dst_ip"] for p in data]).most_common(5),
            "top_ports": Counter([p["dst_port"] for p in data if p["dst_port"]]).most_common(5),
            "protocols": Counter([p["protocol"] for p in data]),
            "total_bytes": sum([p["size"] for p in data])
        }
        return stats