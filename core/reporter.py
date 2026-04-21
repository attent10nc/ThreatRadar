import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class ReportGenerator:
    """
    Модуль для создания человекочитаемых отчетов.
    Выводит данные в консоль и может сохранять в текстовый файл.
    """

    @staticmethod
    def generate_console_summary(stats):
        """Выводит красивую сводку в терминал."""
        if not stats:
            console.print("[yellow][!] Нет данных для анализа.[/yellow]")
            return

        console.print(Panel(f"[bold cyan]ОТЧЕТ ПО СЕТЕВОЙ АКТИВНОСТИ[/bold cyan]\n"
                            f"Всего пакетов: {stats['total_packets']}\n"
                            f"Общий объем: {stats['total_bytes'] / 1024:.2f} KB",
                            expand=False))

        # Таблица топ-источников
        src_table = Table(title="Топ-5 источников (IP)")
        src_table.add_column("IP адрес", style="green")
        src_table.add_column("Кол-во пакетов", justify="right")
        for ip, count in stats["top_sources"]:
            src_table.add_row(ip, str(count))
        console.print(src_table)

        # Таблица протоколов
        proto_table = Table(title="Распределение протоколов")
        proto_table.add_column("Протокол", style="magenta")
        proto_table.add_column("Пакетов", justify="right")
        for proto, count in stats["protocols"].items():
            proto_table.add_row(proto, str(count))
        console.print(proto_table)

    @staticmethod
    def save_text_report(stats, output_path):
        """Сохраняет отчет в .txt файл."""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"ThreatRadar - Итоговый отчет ({time.ctime()})\n")
            f.write("="*40 + "\n")
            f.write(f"Всего пакетов: {stats['total_packets']}\n")
            f.write(f"Общий трафик: {stats['total_bytes']} байт\n\n")
            f.write("ТОП ИСТОЧНИКОВ:\n")
            for ip, count in stats["top_sources"]:
                f.write(f"- {ip}: {count}\n")