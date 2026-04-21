import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

TRAFFIC_LOG_FILE = os.path.join(REPORTS_DIR, "traffic_log.json")
ALERTS_LOG_FILE = os.path.join(REPORTS_DIR, "alerts_log.json")

NETWORK_INTERFACE = None
ANOMALY_THRESHOLD = 15
SYN_FLOOD_THRESHOLD = 50

if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)