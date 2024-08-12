#!/usr/bin/python3

import os
import sys
import re
import json
from tabulate import tabulate  # type: ignore
from termcolor import colored  # type: ignore


class NmapParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = []
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

    def parse_file(self):
        with open(self.file_path, 'r') as file:
            for line in file:
                if self.is_relevant_info_from_line(line):
                    self.parse_line(line)
        return self.data

    @staticmethod
    def is_relevant_info_from_line(line):
        return not line.startswith('#') or 'Host' in line

    def parse_line(self, line):
        ip, ports = self.extract_ip_and_ports(line)
        if not ports:
            return

        self.data.extend(self.port_details(ip, ports))

    @staticmethod
    def extract_ip_and_ports(line):
        parts = line.split()
        ip = parts[1]

        if 'Ports:' not in line:
            return ip, []

        ports_info = line.split('Ports: ')[1]
        ports = ports_info.split(',')

        return ip, ports

    def port_details(self, ip, ports):
        data = []
        for port_info in ports:
            port_details = port_info.split('/')

            if len(port_details) >= 7:
                port, state, protocol, _, service, _, info = port_details[:7]

                cves = self.cve_pattern.findall(info)
                cve_string = ', '.join(cves) if cves else 'N/A'

                data.append({
                    'IP': ip,
                    'Port': port,
                    'Protocol': protocol.lower(),
                    'State': state.lower(),
                    'Service': service.lower(),
                    'Info': info,
                    'CVEs': cve_string
                })

        return data


class CensysParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = []

    def parse_file(self):
        try:
            with open(self.file_path, 'r') as file:
                json_data = json.load(file)

            for entry in json_data:
                ip = entry.get('ip', 'N/A')
                for service in entry.get('services', []):
                    port = service.get('port', 'N/A')
                    protocol = service.get('transport_protocol', 'N/A')
                    extended_service_name = service.get('extended_service_name', 'N/A')

                    self.data.append({
                        'IP': ip,
                        'Port': port,
                        'Protocol': protocol.lower(),
                        'State': 'N/A',
                        'Service': extended_service_name.lower(),
                        'Info': "",
                        'CVEs': 'N/A'
                    })

        except FileNotFoundError:
            print(f"File not found: {self.file_path}", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}", file=sys.stderr)
        except IOError as e:
            print(f"Error reading file: {e}", file=sys.stderr)

        return self.data


class FileManager:
    @staticmethod
    def get_files_paths_to_parse():
        current_directory = os.getcwd()

        files_paths_to_parse = []
        for file in os.listdir(current_directory):
            if file.endswith('.gnmap') or file.endswith('.json'):
                files_paths_to_parse.append(os.path.join(current_directory, file))

        if not files_paths_to_parse:
            print("No files found to parse.", file=sys.stderr)
            sys.exit(1)

        return files_paths_to_parse


class ReportGenerator:
    def __init__(self, all_data):
        self.all_data = all_data

    def print_table(self):
            # [colored(host, "green"), colored(ip, "magenta"), colored(port, "cyan"), not_before, not_after, execute_tls_scan(host)]
        has_cves = any('CVEs' in entry and entry['CVEs'] != 'N/A' for entry in self.all_data)
        headers = ['IP', 'Port', 'Protocol', 'State', 'Service', 'Info']

        if has_cves:
            headers.append('CVEs')

        table = [
            [
                colored(line['IP'], "magenta"), 
                line['Port'], 
                colored(line['Protocol'], "green"),
                line['State'],
                colored(line['Service'], "yellow"), 
                line['Info']
            ] + ([line['CVEs']] if has_cves else []) for line in self.all_data
        ]
        print(tabulate(table, tablefmt='presto', numalign="left"))


class MainController:
    def __init__(self):
        self.file_paths = FileManager.get_files_paths_to_parse()

    def get_data_from_file(self, file_path):
        if file_path.endswith('.gnmap'):
            nmap_parser = NmapParser(file_path)
            return nmap_parser.parse_file()
        elif file_path.endswith('.json'):
            censys_parser = CensysParser(file_path)
            return censys_parser.parse_file()

    def get_all_data_from_files(self):
        all_data = []
        for file_path in self.file_paths:
            all_data.extend(self.get_data_from_file(file_path)) # type: ignore
        return all_data

    def run(self):
        all_data = self.get_all_data_from_files()

        if not all_data:
            print("No data found to display.", file=sys.stderr)
            sys.exit(1)

        report_generator = ReportGenerator(all_data)
        report_generator.print_table()

def main():
    main_controller = MainController()
    main_controller.run()

if __name__ == "__main__":
    main()
