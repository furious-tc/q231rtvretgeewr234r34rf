import asyncio
import json
import os
import re
import sqlite3
import time
from flask import Flask, request, jsonify
from xssScanner import xsscon

app = Flask(__name__)
from scapy.all import sr1
from scapy.layers.inet import IP, ICMP
import nmap as np
from pythonping import ping


class Scanner:
    def __init__(self, remote_ip):
        self.nm = np.PortScanner()
        self.remote_ip = remote_ip

    async def scan_ports(self):#21, 22, 23, 25, 80, 443, 3306, 8080
        scan_raw_result = self.nm.scan(hosts=self.remote_ip, ports="21, 443, 22, 2222, 2020", arguments='--min-rate 100 -n -sT -sC -sV -T5 --min-parallelism 5' , timeout=15)

        del self.nm
        return scan_raw_result

    async def get_data_by_CPE(self, cpe: str):
        cpe = re.search("cpe:\/.+?:(.+)", cpe).groups()[0]
        info = cpe.split(":")
        print(info)
        try:
            conn = sqlite3.connect('vulners.db')
            cursor = conn.cursor()
            data = cursor.execute(f"""SELECT * FROM CVE WHERE cpeUri LIKE '%{info[0]}%' AND cpeUri LIKE '%{info[1]}%' AND cpeUri LIKE '%{info[2]}%';""").fetchall()[0]
            conn.close()
            if data is None:
                raise IndexError
        except IndexError as e:
            conn = sqlite3.connect('vulners.db')
            cursor = conn.cursor()
            data = cursor.execute(
                f"""SELECT * FROM CVE WHERE cpeUri LIKE '%{info[0]}%' AND cpeUri LIKE '%{info[1]}%';""").fetchall()[
                0]
            conn.close()
            
        return data

    async def get_data_from_CVE_ID(self, CVE_ID):
        conn = sqlite3.connect('vulners.db')
        cursor = conn.cursor()
        data = cursor.execute(f"SELECT * FROM CVE WHERE id=?",(CVE_ID, ) ).fetchall()
        conn.close()
        return data

    async def search_vulners(self):
        cves = []
        req = await self.scan_ports()
        for host, result in req['scan'].items():
            if result['status']['state'] == 'up':
                try:
                    for port in result['tcp']:
                        cur_ver = ""
                        cur_soft_title = ""
                        try:
                            try:
                                cur_ver = str(result['tcp'][port]['version'])
                            except KeyError:
                                continue
                            try:
                                cur_soft_title = result['tcp'][port]['product']
                                if ' ' in cur_soft_title:
                                    cur_soft_title = cur_soft_title.split()[0].lower()
                                if ('windows' in cur_soft_title) or ('linux' in cur_soft_title) or (
                                        'microsoft' in cur_soft_title):
                                    cur_soft_title = None
                            except KeyError:
                                continue

                            if cur_soft_title is None or len(cur_soft_title) == 0 or len(cur_ver) == 0:
                                continue
                            try:
                                status = result['tcp'][port]['state']
                            except KeyError:
                                status = "-"
                            try:
                                reason = result['tcp'][port]['reason']
                            except KeyError:
                                reason = "-"
                            try:
                                extra_info = result['tcp'][port]['extrainfo']
                            except KeyError:
                                extra_info = "-"
                            try:
                                name = result['tcp'][port]['name']
                            except KeyError:
                                name = "-"
                            try:
                                cpe = result['tcp'][port]['cpe']
                            except KeyError:
                                cpe = "-"
                            #print(cur_soft_title)

                            cve_data = await self.get_data_by_CPE(cpe)
                            print(cve_data)

                            if cve_data is not None:
                                cve_data = {"CVE_ID": cve_data[1], "serviceName": cur_soft_title,
                                            "port": port, "description": cve_data[3], "cpe": cve_data[4],
                                            "cvss": cve_data[6]}
                                cves.append(cve_data)
                            else:
                                print(123)
                                pass
                        except Exception as e:
                            print(str(e))
                            pass

                except Exception as e:
                    print(str(e))
                    pass

        if len(cves) == 0:
            return None

        return cves


async def scanCVE(remote_ip: str):
    try:
        scanner = Scanner(remote_ip)
        cves = await scanner.search_vulners()
        print(cves)
        #print(cves)
        del scanner
        if cves is None:
            return {"status": True, "code": 200, "ip": str(remote_ip), "cves": "No one CVEs found"}
        return {"status": True, "code": 200, "ip": str(remote_ip), "cves": cves}
    except Exception as e:
        print(str(e))
        del scanner
        return {"status": False, "code": 500, "ip": str(remote_ip)}


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/check/')
def check_cve():
    host = request.args.get('host')
    if host:
        vulners = asyncio.run(scanCVE(str(host)))
        return jsonify(vulners)
    else:
        return jsonify({"status": False, "code": 400, "description": "No remoteIP provided"})


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5054, debug=True)
