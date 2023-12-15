#!/usr/bin/sudo python3

import socket
import nmap
from ipwhois import IPWhois
import customtkinter as ctk
import ipaddress

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

res = {}


class NetworkScanner:
    def __init__(self):
        self.results = []

    def scan_ports(self, target_ips, ports):
        for target_ip in target_ips:
            res[target_ip] = {}
            try:
                print("Scanning target IP: " + target_ip)
                for x in ports:
                    port = int(x)
                    print("Scanning port: " + str(port))
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:
                        service = socket.getservbyport(port)
                        self.results.append({"port": port, "service": service})
                        res[target_ip][str(port)] = service
                        print("Port " + str(port) + " is using")
                    sock.close()
            except Exception as e:
                print(f"Error scanning ports: {e}")

    def scan_hosts(self, target_ips):
        try:
            for ip in target_ips:
                print("Getting information about IP: " + ip)
                nm = nmap.PortScanner()
                nm.scan(ip, arguments="-O")
                host_info = {
                    "country": self.get_country(ip),
                    "provider": self.get_provider(ip)
                }
                self.results.append(host_info)
                res[ip]["country"] = host_info["country"]
                res[ip]["provider"] = host_info["provider"]
        except Exception as e:
            print(f"Error scanning hosts: {e}")

    def get_country(self, ip):
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap()
            return result.get('asn_description', 'N/A')
        except Exception as e:
            print(f"Error getting country information: {e}")
            return "N/A"

    def get_provider(self, ip):
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap()
            return result.get('asn_registry', 'N/A')
        except Exception as e:
            print(f"Error getting provider information: {e}")
            return "N/A"

    def display_results(self):
        print(res)


scanner = NetworkScanner()


class GUI(ctk.CTk):
    def __init__(self):
        ctk.CTk.__init__(self)
        self.full_scan = None
        self.full_var = None
        self.ports = None
        self.ips = None
        self.toplevel_window = None
        self.title("IP Scaner")
        self.geometry("600x500+700+280")
        self.create_widgets()

    def create_widgets(self):
        ip_label = ctk.CTkLabel(self, text="Введите IP-адреса:", text_color="white")
        ip_label.pack(pady=10)

        self.ips = ctk.CTkTextbox(self, width=200, height=100)
        self.ips.pack()

        ports_label = ctk.CTkLabel(self, text="Введите порты:")
        ports_label.pack(pady=10)

        self.ports = ctk.CTkTextbox(self, width=200, height=100)
        self.ports.pack()

        self.full_var = ctk.StringVar(value="off")
        self.full_scan = ctk.CTkCheckBox(self, text="Полное сканирование", onvalue="on", offvalue="off",
                                         variable=self.full_var, command=self.checkbox_event)
        self.full_scan.pack(pady=10)

        start_button = ctk.CTkButton(self, text="Запуск", command=self.start)
        start_button.pack()

    def checkbox_event(self):
        if self.full_var.get() == "off":
            self.ports.configure(state="normal")
        else:
            self.ports.configure(state="disabled")

    def start(self):
        to_scan = []
        if self.full_var.get() == "on":
            to_scan = [str(x) for x in range(1, 65536)]
        else:
            to_scan = self.ports.get("0.0", ctk.END)
            to_scan = to_scan.split('\n')
            if len(to_scan) != 1: to_scan.pop()

        ip_list = self.ips.get("0.0", ctk.END)
        ip_list = ip_list.split('\n')
        if len(ip_list) != 1: ip_list.pop()

        ips = []
        for ip in ip_list:
            ip_network = ipaddress.IPv4Network(ip)
            for x in ip_network:
                ips.append(str(x))

        scanner.scan_ports(ips, to_scan)
        scanner.scan_hosts(ips)
        self.open_toplevel()

    def open_toplevel(self):
        if self.toplevel_window is None or not self.toplevel_window.winfo_exists():
            self.toplevel_window = ToplevelWindow(res)
        else:
            self.toplevel_window.focus()


class ToplevelWindow(ctk.CTkToplevel):
    def __init__(self, info):
        super().__init__()
        self.geometry("400x300")

        self.label = ctk.CTkLabel(self, text="Результат")
        self.label.pack(padx=20, pady=20)
        textbox = ctk.CTkTextbox(self, width=400, height=300)
        textbox.pack()
        tb = ''
        for ip, ip_info in info.items():
            tb += f'--{ip}--\n'
            tb += f'    Found {len(ip_info)-2} opened ports:\n'
            for key, val in ip_info.items():
                tb += f'    {key}: {val}\n'

        textbox.insert("0.0", tb)
        with open("results.txt", "w") as file:
            file.write(tb)


if __name__ == "__main__":
    # 185.174.137.192
    gui = GUI()
    gui.mainloop()
