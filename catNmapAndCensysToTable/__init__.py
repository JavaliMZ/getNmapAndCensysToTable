#!/usr/bin/python3

import os
import sys
import re
import json
from tabulate import tabulate

def is_relevant_info_from_line_nmap(line):
    return not line.startswith('#') or 'Host' in line

def extract_ip_and_ports_from_line_nmap(line):
    parts = line.split()
    ip = parts[1]

    if 'Ports:' not in line:
        return ip, []

    ports_info = line.split('Ports: ')[1]
    ports = ports_info.split(',')

    return ip, ports


def parse_grepable_nmap_output(file_path):
    data = []
    cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

    with open(file_path, 'r') as file:
        for line in file:
            if not is_relevant_info_from_line_nmap(line):
                continue
            
            ip, ports = extract_ip_and_ports_from_line_nmap(line)
            if not ports:
                continue


            for port_info in ports:
                port_details = port_info.split('/')

                if len(port_details) >= 7:
                    port, state, protocol, _, service, _, info = port_details[:7]

                    cves = cve_pattern.findall(info)
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

def parse_censys_json(file_path):
    data = []

    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)

        for entry in json_data:
            ip = entry.get('ip', 'N/A')
            for service in entry.get('services', []):
                port = service.get('port', 'N/A')
                protocol = service.get('transport_protocol', 'N/A')
                extended_service_name = service.get('extended_service_name', 'N/A')

                data.append({
                    'IP': ip,
                    'Port': port,
                    'Protocol': protocol.lower(),
                    'State': 'N/A',
                    'Service': extended_service_name.lower(),
                    'Info': "",
                    'CVEs': 'N/A'
                })
    except FileNotFoundError:
        print(f"File not found: {file_path}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}", file=sys.stderr)
    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)

    return data

def print_table(data):
    has_cves = any('CVEs' in entry and entry['CVEs'] != 'N/A' for entry in data)
    headers = ['IP', 'Port', 'Protocol', 'State', 'Service', 'Info']

    if has_cves:
        headers.append('CVEs')

    table = [
        [line['IP'], line['Port'], line['Protocol'], line['State'],
         line['Service'], line['Info']] + ([line['CVEs']] if has_cves else []) for line in data
    ]
    # print(tabulate(table, headers=headers, tablefmt='simple', numalign="left"))
    print(tabulate(table, tablefmt='plain', numalign="left"))

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

def get_all_data_from_files(files_paths_to_parse):
    all_data = []
    for file_path in files_paths_to_parse:
        if file_path.endswith('.gnmap'):
            file_data = parse_grepable_nmap_output(file_path)
            all_data.extend(file_data)
        elif file_path.endswith('.json'):
            file_data = parse_censys_json(file_path)
            all_data.extend(file_data)

    return all_data

def main():
    files_paths_to_parse = get_files_paths_to_parse()
    all_data = get_all_data_from_files(files_paths_to_parse)

    if not all_data:
        print("No data found to display.", file=sys.stderr)
        sys.exit(1)

    print_table(all_data)

if __name__ == "__main__":
    main()
