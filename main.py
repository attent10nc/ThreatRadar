import os
import sys
import time
import json
import logging
from core.packet_sniffer import PacketSniffer
from core.anomaly_detector import AnomalyDetector
from core.threat_classifier import ThreatClassifier
from core.analyzer import TrafficAnalyzer
from core.reporter import ReportGenerator
from config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")
logger = logging.getLogger("ThreatRadar.Main")

TRAFFIC_BUFFER = []
MAX_BUFFER_SIZE = 50

def save_traffic_to_log(packet_info):
    global TRAFFIC_BUFFER
    TRAFFIC_BUFFER.append(packet_info)

    if len(TRAFFIC_BUFFER) >= MAX_BUFFER_SIZE:
        try:
            data = []
            if os.path.exists(settings.TRAFFIC_LOG_FILE):
                with open(settings.TRAFFIC_LOG_FILE, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        data = []

            data.extend(TRAFFIC_BUFFER)
            data = data[-10000:]

            with open(settings.TRAFFIC_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)

            TRAFFIC_BUFFER.clear()
        except Exception as e:
            logger.error(f"Ошибка записи traffic_log: {e}")

def main():
    print("=" * 70)
    print(" 🛡️  ThreatRadar - Network Threat Monitoring & Analysis System")
    print("=" * 70)

    classifier = ThreatClassifier()

    def handle_alert(alert_data):
        threat_info = classifier.process_alert(alert_data)
        if threat_info:
            print(f"\n[!!!] УГРОЗА: {threat_info['threat_type']} от {threat_info['src_ip']} (Risk: {threat_info['risk_score']})")

    detector = AnomalyDetector(alert_callback=handle_alert)

    def handle_packet(p):
        save_traffic_to_log(p)
        detector.analyze(p)

    sniffer = PacketSniffer(interface=settings.NETWORK_INTERFACE, callback=handle_packet)

    try:
        sniffer.start()
        logger.info(f"Мониторинг запущен на интерфейсе: {settings.NETWORK_INTERFACE or 'Default'}")
        logger.info("Для остановки и формирования финального отчета нажмите Ctrl+C...")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n")
        logger.info("Остановка захвата данных. Начинаю финальный анализ...")
        sniffer.stop()

        analyzer = TrafficAnalyzer(settings.TRAFFIC_LOG_FILE)
        stats = analyzer.get_stats()

        reporter = ReportGenerator()
        reporter.generate_console_summary(stats)

        if stats:
            report_filename = f"summary_{int(time.time())}.txt"
            report_path = os.path.join(settings.REPORTS_DIR, report_filename)
            reporter.save_text_report(stats, report_path)
            logger.info(f"Текстовый отчет сохранен в: {report_path}")

        logger.info("ThreatRadar успешно завершил работу.")

if __name__ == "__main__":
    main()