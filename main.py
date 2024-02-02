from tabulate import tabulate
from dotenv import load_dotenv
from datetime import datetime
from vmanage import sdwan_manager
import os
import json
import csv
import re


def get_vmanage_credentials():

    load_dotenv()
    host = os.getenv("VMANAGE")
    port = os.getenv("PORT")
    user = os.getenv("USERNAME")
    pwd = os.getenv("PASSWORD")

    return host, port, user, pwd


def convert_epoch_to_human(epoch_time):

    datetime_obj = datetime.fromtimestamp(epoch_time)
    human_readable_time = datetime_obj.strftime("%Y-%m-%d %H:%M:%S")

    return human_readable_time


def parse_tunnels_down(data):

    inactive_tunnels = []
    system_ips = set()
    titles = [
        "vdevice-host-name",
        "vdevice-name",
        "site-id",
        "device-state",
        "sig-state",
    ]

    for t in data:

        epochtime = int(str(t.get("lastupdated"))[:-3])
        human_readable_time = convert_epoch_to_human(epochtime)
        if t.get("sig-state") in ["DOWN"] and t.get("device-state") in ["Down"]:
            tunnel = [t.get(title) for title in titles]
            tunnel.append(human_readable_time)
            inactive_tunnels.append(tunnel)
            system_ips.add(t.get("vdevice-name"))

    return inactive_tunnels, list(system_ips)


def parse_cluster_status(data):

    _ = data.pop(0)
    headers = [
        "statistics-db",
        "application-server",
        "messaging-server",
        "configuration-db",
        "container-manager",
        "deviceIP",
    ]
    cluster_health_status = [headers]

    for items in data:
        values = []
        for key in headers:
            if items.get(key):
                values.append(items.get(key))
            else:
                values.append(False)
        cluster_health_status.append(values)

    return cluster_health_status


def parse_events(data):

    events = data

    return events


def get_vmanage_health(session, vmanage_system_ips):

    headers = ["SYSTEM IP", "HOSTNAME", "UP TIME", "MEM USE", "DISK USE", "CPU USE"]
    vmanage_health_status = [headers]

    for vmanage in vmanage_system_ips:

        response = session.send_request(
            "GET", f"/device/system/status?deviceId={vmanage}", body={}
        )
        data = response.json()["data"][0]
        mem_use = (
            str(round(int(data["mem_used"]) * 100 / int(data["mem_total"]), 2)) + " %"
        )
        disk_use = data["disk_use"] + " %"
        cpu_use = str(round(100 - float(data["cpu_idle"]), 2)) + " %"
        new_row = [
            data["vdevice-name"],
            data["vdevice-host-name"],
            data["uptime"],
            mem_use,
            disk_use,
            cpu_use,
        ]

        vmanage_health_status.append(new_row)

    return vmanage_health_status


def create_query(list_of_IPs, list_of_events, list_of_severities, n_hours):

    rules_set = []

    if list_of_IPs:
        rules_set.append(
            {
                "field": "system_ip",
                "type": "string",
                "value": list_of_IPs,
                "operator": "in",
            }
        )

    if list_of_events:
        rules_set.append(
            {
                "field": "eventname",
                "type": "string",
                "value": list_of_events,
                "operator": "in",
            }
        )

    if list_of_severities:
        rules_set.append(
            {
                "field": "severity_level",
                "type": "string",
                "value": list_of_severities,
                "operator": "in",
            }
        )

    if n_hours:

        rules_set.append(
            {
                "field": "entry_time",
                "type": "date",
                "value": n_hours,
                "operator": "last_n_hours",
            }
        )

    query = json.dumps(
        {"query": {"condition": "AND", "rules": rules_set}, "size": 10000}, indent=4
    )

    if rules_set:
        return query


def dump_events_csv(data, filename, pattern="."):

    headers = list(data[0].keys())
    values = list(
        line.values() for line in data if re.search(pattern, str(line.values()))
    )

    with open(filename, "w") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(headers)
        csv_writer.writerows(values)

    print(f"Archivo {filename} guardado!")


if __name__ == '__main__':

    # Conexion a vManage
    
    host, port, user, pwd = get_vmanage_credentials()
    session = sdwan_manager(host, port, user, pwd)

    # Monitoreo de Tunneles SIG

    response = session.send_request(
        action="GET", resource="/device/sig/getSigTunnelList", body={}
    )
    data = response.json()["data"]
    inactive_tunnels, system_ips = parse_tunnels_down(data)
    sig_tunnels_table = tabulate(
        inactive_tunnels,
        tablefmt="pretty",
        headers=[
            "hostname",
            "system-ip",
            "site-id",
            "device-state",
            "sig-state",
            "lastupdated",
        ],
    )
    print(sig_tunnels_table, "\n")

    # Monitoreo de Salud del Cluster de vManages

    response = session.send_request(
        action="GET", resource="/clusterManagement/health/status", body={}
    )
    data = response.json()["data"]
    cluster_health_status = parse_cluster_status(data)
    cluster_status_table = tabulate(
        cluster_health_status,
        tablefmt="pretty",
        headers="firstrow",
    )
    print(cluster_status_table, "\n")

    # Monitoreo de Recursos en vManage (Up Time, Memoria, Disco, CPU)

    response = session.send_request(
        action="GET", resource="/system/device/controllers?model=vmanage", body={}
    )
    data = response.json()["data"]
    vmanage_system_ips = [
        item.get("managementSystemIP") for item in data if item.get("managementSystemIP")
    ]
    vmanage_health_status = get_vmanage_health(session, vmanage_system_ips)
    vmanage_health_table = tabulate(
        vmanage_health_status,
        tablefmt="pretty",
        headers="firstrow",
    )
    print(vmanage_health_table, "\n")
    
    # Monitoreo de Eventos - Tuneles SIG

    query = create_query(system_ips, ["ftm-tunnel-tracker"], ["critical"], ["1"])
    if query:
        response = session.send_request(action="POST", resource="/event", body=query)
        data = response.json()["data"]
        print("Payload:")
        print(query)
        dump_events_csv(data, "reporte_tunneles_SIG.csv", "SDWAN-CJF-774-RT01")

    # Monitoreo de Eventos - Sesiones BFD abajo
    
    query = create_query(None, ["bfd-state-change"], ["major"], ["1"])
    if query:
        response = session.send_request(action="POST", resource="/event", body=query)
        data = response.json()["data"]
        print("Payload:")
        print(query)
        dump_events_csv(data, "reporte_bfd.csv", "new-state=down")

    # Desconexion de vManage
    
    session.logout()
