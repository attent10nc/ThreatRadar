import time
import threading
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP

logger = logging.getLogger("ThreatRadar.Sniffer")

class PacketSniffer:
    """
    Модуль захвата сетевого трафика.
    Работает в отдельном потоке, чтобы не блокировать основной интерфейс.
    Извлекает из пакетов полезные данные и передает их через callback-функцию.
    """

    def __init__(self, interface=None, bpf_filter="ip", callback=None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.callback = callback

        self._stop_event = threading.Event()
        self._thread = None
        self.packet_count = 0

    def start(self):
        """Запуск перехвата пакетов в фоновом потоке."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Сниффер уже запущен!")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        logger.info(f"Сниффер запущен на интерфейсе: {self.interface or 'Default'}")

    def stop(self):
        """Остановка перехвата пакетов."""
        logger.info("Остановка сниффера...")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info(f"Сниффер остановлен. Всего пакетов обработано: {self.packet_count}")

    def _sniff_loop(self):
        """Основной цикл захвата Scapy."""
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._parse_packet,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Ошибка при захвате трафика: {e}")

    def _parse_packet(self, packet):
        """Парсинг сырого пакета Scapy в удобный словарь."""
        if not packet.haslayer(IP):
            return

        self.packet_count += 1

        ip_layer = packet[IP]
        packet_info = {
            "timestamp": time.time(),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "size": len(packet),
            "protocol": "OTHER",
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None
        }

        if packet.haslayer(TCP):
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
            packet_info["tcp_flags"] = str(packet[TCP].flags)

        elif packet.haslayer(UDP):
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport

        elif packet.haslayer(ICMP):
            packet_info["protocol"] = "ICMP"

        if self.callback:
            self.callback(packet_info)