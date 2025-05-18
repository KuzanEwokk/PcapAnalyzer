from textual.app import App, ComposeResult
from textual.widgets import Button, DataTable, Input, ListView, ListItem, Static
from textual.containers import Center
from textual.screen import Screen
import pandas as pd
import matplotlib.pyplot as plt
import io
import time
from datetime import datetime
from threading import Thread
import os
from pathlib import Path
import wczytanieDanych
from nfstream import NFStreamer
import queue
from textual import work
from PIL import Image




# Placeholder functions for your custom logic
def analize_pcap(file_path: str) -> pd.DataFrame:
    return pd.DataFrame({
        "Source": ["192.168.1.1", "192.168.1.2"],
        "Destination": ["192.168.1.3", "192.168.1.4"],
        "Protocol": ["TCP", "UDP"],
        "Length": [150, 200],
    })

def test_flow(interface: str, callback):
    for i in range(10):
        callback(f"Alert {i + 1}", datetime.now().strftime("%H:%M:%S"))
        time.sleep(1)


class MainMenu(Screen):
    """Ekran głównego menu."""
    def compose(self) -> ComposeResult:
        yield Center(
            Static("Wybierz akcję:"),
            Static("<Tab>/<Shift+Tab> następny/poprzedni. <Enter> wybierz"),
            Button("Wczytaj PCAP", id="open-pcap-screen"),
            Button("Monitoruj Interfejs", id="open-interface-screen"),
            Button("Zmodyfikuj model ML", id="open-ml-screen"),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "open-pcap-screen":
            self.app.push_screen("pcap_screen")
        elif event.button.id == "open-interface-screen":
            self.app.push_screen("interface_screen")
        elif event.button.id == "open-ml-screen":
            self.app.push_screen("ml_screen")


class PCAPScreen(Screen):
    """Ekran wczytywania i wyświetlania PCAP."""
    def compose(self) -> ComposeResult:
        yield Center(
            Button("Powrót do menu", id="back-to-menu"),
            Input(placeholder="path to .pcap", id="path-input"),
            Static("",id="info"),
            Button("Wczytaj plik PCAP", id="load-pcap"),
            DataTable(id="pcap-table"),
            DataTable(id="pcap-table2"),
            DataTable(id="podejrzane"),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-to-menu":
            self.app.pop_screen()
        elif event.button.id == "load-pcap":
            self.load_pcap()

    def load_pcap(self) -> None:
        file_path = self.get_entered_file()
        if file_path == "":
            return
        df = wczytanieDanych.wczytanieDanych(file_path)
        table = self.query_one("#pcap-table", DataTable)
        table.clear()
        table.add_columns(*df[0].columns)
        table.add_rows(df[0].values)
        tabulator = self.query_one("#pcap-table2", DataTable)
        tabulator.clear()
        tabulator.add_columns(*df[1].columns)
        tabulator.add_rows(df[1].values)
        podejrzane = self.query_one("#podejrzane", DataTable)
        podejrzane.clear()
        podejrzane.add_columns(*df[2].columns)
        podejrzane.add_rows(df[2].values)
    
    def get_entered_file(self) -> str:
        input_field = self.query_one("#path-input", Input)
        file_path = input_field.value.strip()

        if not file_path:
            info = self.query_one("#info", Static)
            info.update("Ścieżka jest pusta")
        
        file_path = Path(file_path)
        if file_path.is_file():  # Sprawdza, czy ścieżka jest plikiem
            try:
                with open(file_path, 'r'):
                    pass
            except Exception as e:
                info = self.query_one("#info", Static)
                info.update(f"Nie udało się otworzyć pliku. Błąd: {e}")
                return ""
        else:
            info = self.query_one("#info", Static)
            info.update("Podana ścieżka nie prowadzi do pliku.")
            return ""
        
        return file_path

class InterfaceScreen(Screen):
    alert_queueueueueue = queue.Queue()
    alerts = []
    detection_rules = []
    times=[0,0]
    """Ekran monitorowania interfejsów."""
    def compose(self) -> ComposeResult:
        yield Center(
            Button("Powrót do menu", id="back-to-menu"),
            Static("Wpisz nazwę interfejsu:"),
            Input(placeholder="np. eth0", id="interface-input"),
            Static("", id="info"),
            Button("Start Monitoringu", id="start-monitoring"),
            Button("Stop Monitoringu", id="stop-monitoring", disabled=True),
            ListView(id="alerts-list"),
            Static(id="alerts-chart"),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-to-menu":
            self.app.pop_screen()
        elif event.button.id == "start-monitoring":
            self.start_monitoring()
        elif event.button.id == "stop-monitoring":
            self.stop_monitoring()

    def start_monitoring(self) -> None:
        self.times[0]=datetime.now().strftime('%H:%M:%S')
        interface = self.get_entered_interface()
        self.alerts=[]
        #alert_list = self.query_one("#alerts-list", ListView)
        #alert_list.clear()
        if not interface:
            return
        if self.init_rules() == False: return

        self.query_one("#start-monitoring", Button).disabled = True
        self.query_one("#stop-monitoring", Button).disabled = False
        self.monitoring_thread = Thread(
            target=self.monitor_interface, args=(interface,)
        )
        self.monitoring_thread.start()
        self.timerans = self.set_interval(0.1,self.washing_refresh)
                
    def washing_refresh(self):
        if(self.alert_queueueueueue.qsize!=0):
            try:
                self.query_one("#alerts-list", ListView).append(ListItem(Static(self.alert_queueueueueue.get(timeout=0.1))))
            except Exception:
                pass

    def init_rules(self):
        try:
            import detection_rules as DList
            self.detection_rules = DList.get_list()
        except Exception as e:
            info = self.query_one("#info", Static)
            info.update(f"Error while loading detection rules: {str(e)}")
            return False

        rules_list = []
        for i in self.detection_rules:
            rules_list.append( str(i.__name__) )
        
        info = self.query_one("#info", Static)
        info.update(f"loaded rules: {str(rules_list)}")
        return True

    def stop_monitoring(self) -> None:
        self.times[1]=datetime.now().strftime('%H:%M:%S')
        self.monitoring = False
        self.query_one("#start-monitoring", Button).disabled = False
        self.query_one("#stop-monitoring", Button).disabled = True
        self.generate_alert_chart()
        self.timerans.stop
        

    def monitor_interface(self, interface: str) -> None:
        self.monitoring = True
        

        streamer = NFStreamer(source=interface)

        # Analiza flow
        for flow in streamer:
            for rule in self.detection_rules:
                result, message = rule(flow)
                timestamp = datetime.now().strftime('%H:%M:%S')
                if result:
                    self.alert_queueueueueue.put(f"{message} : {timestamp}")
                    #self.query_one("#alerts-list", ListView).append(ListItem(Static("Nie podano nazwy interfejsu! yess")))
                    self.alerts.append([message, timestamp])
                    
                    
                    

    def generate_alert_chart(self) -> None:
        timestamps = [alert[1] for alert in self.alerts]
        counts=({self.times[0] : 0})
        counts.update({ts: timestamps.count(ts) for ts in set(timestamps)})
        counts.update({self.times[1] : 0})
        fig, ax = plt.subplots()
        ax.bar(counts.keys(), counts.values())
        ax.set_title("Alert Count Over Time")
        ax.set_xlabel("Time")
        ax.set_ylabel("Alerts")
        plt.show()

    def get_entered_interface(self) -> str:
        input_field = self.query_one("#interface-input", Input)
        interface = input_field.value.strip()
        if not interface:
            self.query_one("#alerts-list", ListView).append(
                ListItem(Static("Nie podano nazwy interfejsu!"))
            )
        return interface


class NetworkAnalyzerApp(App):
    """Główna aplikacja."""
    CSS_PATH = "styles.css"

    def on_mount(self) -> None:
        self.install_screen(MainMenu(), name="main_menu")
        self.install_screen(PCAPScreen(), name="pcap_screen")
        self.install_screen(InterfaceScreen(), name="interface_screen")
        self.install_screen(MLscreen(), name="ml_screen")
        self.push_screen("main_menu")
        


class MLscreen(Screen):
    """Ekran do uczenia modelu ML."""
    def compose(self) -> ComposeResult:
        yield Center(
            Button("Powrót do menu", id="back-to-menu"),
            Static("Podaj poprawny ruch PCAP i niepoprawny ruch PCAP by zmodyfikować wbudowany system ML"),
            Input(placeholder="path to good .pcap", id="path-input1"),
            Input(placeholder="path to bad .pcap", id="path-input2"),
            Static("",id="info"),
            Button("Naucz model na danych", id="load-pcap"),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-to-menu":
            self.app.pop_screen()
        elif event.button.id == "load-pcap":
            self.load_pcaps()

    def load_pcaps(self) -> None:
        file_path = self.get_entered_files()
        if file_path == "":
            return
        dobry = file_path[0]
        zly = file_path[1]
        wczytanieDanych.wczytanieDanychML(dobry,zly)
    
    def get_entered_files(self) -> str:
        input_field = self.query_one("#path-input1", Input)
        file_path1 = input_field.value.strip()

        if not file_path1:
            info = self.query_one("#info", Static)
            info.update("Ścieżka 1 jest pusta")
        
        file_path1 = Path(file_path1)
        if file_path1.is_file():  # Sprawdza, czy ścieżka jest plikiem
            try:
                with open(file_path1, 'r'):
                    pass
            except Exception as e:
                info = self.query_one("#info", Static)
                info.update(f"Nie udało się otworzyć pliku 1. Błąd: {e}")
                return ""
        else:
            info = self.query_one("#info", Static)
            info.update("Podana ścieżka 1 nie prowadzi do pliku.")
            return ""
        
        input_field2 = self.query_one("#path-input2", Input)
        file_path2 = input_field2.value.strip()

        if not file_path2:
            info = self.query_one("#info", Static)
            info.update("Ścieżka 2 jest pusta")
        
        file_path2 = Path(file_path2)
        if file_path2.is_file():  # Sprawdza, czy ścieżka jest plikiem
            try:
                with open(file_path2, 'r'):
                    pass
            except Exception as e:
                info = self.query_one("#info", Static)
                info.update(f"Nie udało się otworzyć pliku 2. Błąd: {e}")
                return ""
        else:
            info = self.query_one("#info", Static)
            info.update("Podana ścieżka 2 nie prowadzi do pliku.")
            return ""
        
        return [file_path1,file_path2]

if __name__ == "__main__":
    app = NetworkAnalyzerApp()
    app.run()
    


