import logging

logger = logging.getLogger("ThreatRadar.ThreatClassifier")


class ThreatClassifier:
    """
    Классификатор сетевых угроз.
    Принимает сырые алерты от детектора аномалий, обогащает их контекстом,
    классифицирует по вектору атаки и предоставляет рекомендации по защите (Mitigation).
    """

    def __init__(self):
        self.taxonomy = {
            "Port Scan": {
                "category": "Reconnaissance (Разведка)",
                "risk_base": 40,
                "mitigation": "Настроить Rate-Limiting. Добавить IP-адрес атакующего во временный черный список."
            },
            "SYN Flood": {
                "category": "Denial of Service (DoS)",
                "risk_base": 85,
                "mitigation": "Включить защиту SYN-cookies на уровне ОС. Ограничить количество полуоткрытых TCP-соединений."
            },
            "Brute Force": {
                "category": "Credential Access (Доступ к учетным данным)",
                "risk_base": 70,
                "mitigation": "Внедрить защиту от перебора (fail2ban). Использовать аутентификацию по ключам."
            },
            "Unknown": {
                "category": "Unclassified Anomaly",
                "risk_base": 10,
                "mitigation": "Требуется ручной анализ логов трафика."
            }
        }

    def process_alert(self, alert_data):
        """
        Классифицирует входящий алерт и возвращает обогащенный объект угрозы.
        """
        if not alert_data:
            return None

        threat_type = alert_data.get("type", "Unknown")
        src_ip = alert_data.get("src_ip", "Unknown")

        classification = self.taxonomy.get(threat_type, self.taxonomy["Unknown"])

        final_risk_score = classification["risk_base"]

        if alert_data.get("severity") == "CRITICAL":
            final_risk_score = min(100, final_risk_score + 15)
        elif alert_data.get("severity") == "HIGH":
            final_risk_score = min(100, final_risk_score + 5)

        enriched_threat = {
            "timestamp": alert_data.get("timestamp"),
            "src_ip": src_ip,
            "dst_ip": alert_data.get("dst_ip"),
            "threat_type": threat_type,
            "category": classification["category"],
            "severity": alert_data.get("severity", "LOW"),
            "risk_score": final_risk_score,
            "description": alert_data.get("message", "Описание отсутствует"),
            "mitigation": classification["mitigation"]
        }

        logger.info(f"Угроза классифицирована: {threat_type} от {src_ip} | Risk Score: {final_risk_score}")

        return enriched_threat