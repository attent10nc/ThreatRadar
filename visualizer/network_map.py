import os
import json
import networkx as nx
import plotly.graph_objects as go

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAFFIC_LOG_FILE = os.path.join(BASE_DIR, "reports", "traffic_log.json")
ALERTS_LOG_FILE = os.path.join(BASE_DIR, "reports", "alerts_log.json")
MAP_OUTPUT_FILE = os.path.join(BASE_DIR, "reports", "network_map.html")

def load_json(filepath):
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def generate_network_map():
    """Генерирует интерактивную графовую карту сети на основе логов трафика и угроз."""
    traffic = load_json(TRAFFIC_LOG_FILE)
    alerts = load_json(ALERTS_LOG_FILE)

    G = nx.Graph()
    connections = {}

    for pkt in traffic:
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")
        if src and dst:
            edge = tuple(sorted((src, dst)))
            connections[edge] = connections.get(edge, 0) + 1

    for (src, dst), weight in connections.items():
        G.add_edge(src, dst, weight=weight)

    if not G.nodes:
        print("[-] Нет данных о трафике для построения графа.")
        return

    risky_nodes = {}
    for alert in alerts:
        src = alert.get("src_ip")
        if src:
            risk = alert.get("risk_score", 0)
            if src not in risky_nodes or risk > risky_nodes[src]:
                risky_nodes[src] = risk

    pos = nx.spring_layout(G, seed=42)

    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#4b5563'),
        hoverinfo='none',
        mode='lines'
    )

    node_x = []
    node_y = []
    node_color = []
    node_text = []
    node_size = []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        node_connections = sum([connections.get(tuple(sorted((node, adj))), 0) for adj in G.neighbors(node)])
        calculated_size = min(40, 10 + (node_connections * 1.5))
        node_size.append(calculated_size)

        if node in risky_nodes:
            node_color.append('#ef4444')
            node_text.append(f"<b>IP: {node}</b><br>Уровень риска: {risky_nodes[node]}<br>Пакетов: {node_connections}")
        else:
            node_color.append('#10b981')
            node_text.append(f"<b>IP: {node}</b><br>Статус: Норма<br>Пакетов: {node_connections}")

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        hovertext=node_text,
        marker=dict(
            showscale=False,
            color=node_color,
            size=node_size,
            line=dict(width=2, color='#1f2937')
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace],
         layout=go.Layout(
            title='<br>Интерактивная топология сети ThreatRadar',
            titlefont=dict(size=20, color='#67e8f9'),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=60),
            plot_bgcolor='#111827',
            paper_bgcolor='#111827',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
    )

    fig.write_html(MAP_OUTPUT_FILE)
    print(f"[+] Карта сети успешно сгенерирована и сохранена: {MAP_OUTPUT_FILE}")

if __name__ == "__main__":
    generate_network_map()