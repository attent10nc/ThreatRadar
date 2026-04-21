import os
import json
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAFFIC_LOG_FILE = os.path.join(BASE_DIR, "reports", "traffic_log.json")
ALERTS_LOG_FILE = os.path.join(BASE_DIR, "reports", "alerts_log.json")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatRadar Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.plot.ly/plotly-2.24.1.min.js"></script>
</head>
<body class="bg-gray-900 text-white p-6 font-sans">
    <div class="max-w-7xl mx-auto">
        <h1 class="text-3xl font-bold mb-6 text-cyan-400 flex items-center">
            <span class="mr-3">☠️️</span> 
        </h1>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700">
                <h2 class="text-xl text-gray-400">Всего пакетов</h2>
                <p id="totalPackets" class="text-4xl font-bold text-blue-400 mt-2">0</p>
            </div>
            <div class="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700">
                <h2 class="text-xl text-gray-400">Угроз обнаружено</h2>
                <p id="totalAlerts" class="text-4xl font-bold text-red-500 mt-2">0</p>
            </div>
            <div class="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700">
                <h2 class="text-xl text-gray-400">Статус системы</h2>
                <p class="text-2xl font-bold text-green-400 mt-2 flex items-center">
                    <span class="animate-pulse w-3 h-3 bg-green-500 rounded-full mr-2"></span> Мониторинг активен
                </p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700 col-span-2">
                <h2 class="text-xl font-bold mb-4 border-b border-gray-700 pb-2">Последние угрозы</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead>
                            <tr class="text-gray-400 text-sm uppercase">
                                <th class="py-2 px-4">Время</th>
                                <th class="py-2 px-4">Тип</th>
                                <th class="py-2 px-4">Источник</th>
                                <th class="py-2 px-4">Риск</th>
                            </tr>
                        </thead>
                        <tbody id="alertsTableBody">
                            <!-- Заполняется через JS -->
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700">
                <h2 class="text-xl font-bold mb-4 border-b border-gray-700 pb-2">Трафик по протоколам</h2>
                <div id="protocolChart" class="h-64"></div>
            </div>
        </div>
    </div>

    <script>
        async function fetchData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();

                document.getElementById('totalPackets').textContent = data.total_packets.toLocaleString();
                document.getElementById('totalAlerts').textContent = data.total_alerts.toLocaleString();

                const tbody = document.getElementById('alertsTableBody');
                tbody.innerHTML = '';

                if (data.recent_alerts.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-gray-500">Угроз пока не обнаружено</td></tr>';
                } else {
                    data.recent_alerts.forEach(alert => {
                        const riskColor = alert.risk_score > 75 ? 'text-red-500' : 'text-yellow-400';
                        const timeStr = alert.timestamp ? new Date(alert.timestamp * 1000).toLocaleTimeString() : '-';
                        tbody.innerHTML += `
                            <tr class="border-t border-gray-700 hover:bg-gray-750">
                                <td class="py-3 px-4 text-sm text-gray-300">${timeStr}</td>
                                <td class="py-3 px-4 font-semibold text-red-400">${alert.threat_type}</td>
                                <td class="py-3 px-4 font-mono text-sm text-gray-300">${alert.src_ip}</td>
                                <td class="py-3 px-4 font-bold ${riskColor}">${alert.risk_score}</td>
                            </tr>
                        `;
                    });
                }

                const labels = Object.keys(data.protocols);
                const values = Object.values(data.protocols);

                if (labels.length > 0) {
                    Plotly.newPlot('protocolChart', [{
                        values: values,
                        labels: labels,
                        type: 'pie',
                        hole: .5,
                        marker: { colors: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'] },
                        textinfo: 'label+percent',
                        textfont: { color: '#ffffff' }
                    }], {
                        paper_bgcolor: 'rgba(0,0,0,0)',
                        plot_bgcolor: 'rgba(0,0,0,0)',
                        margin: { t: 10, b: 10, l: 10, r: 10 },
                        showlegend: true,
                        legend: { font: { color: '#9ca3af' } }
                    }, {displayModeBar: false});
                }
            } catch (error) {
                console.error('Ошибка загрузки данных:', error);
            }
        }

        fetchData();
        setInterval(fetchData, 2000); // Автообновление каждые 2 секунды
    </script>
</body>
</html>
"""


def load_json(filepath):
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/data")
def api_data():
    traffic = load_json(TRAFFIC_LOG_FILE)
    alerts = load_json(ALERTS_LOG_FILE)

    protocols = {}
    for pkt in traffic:
        proto = pkt.get("protocol", "OTHER")
        protocols[proto] = protocols.get(proto, 0) + 1

    recent_alerts = alerts[-10:][::-1]

    return jsonify({
        "total_packets": len(traffic),
        "total_alerts": len(alerts),
        "protocols": protocols,
        "recent_alerts": recent_alerts
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)