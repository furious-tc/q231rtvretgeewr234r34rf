import asyncio
import json
import os
import re
import sqlite3
import time
from flask import Flask, request, jsonify
import asynsqlapi

app = Flask(__name__)


async def dataToJson(info: list|set):
    if type(info) is list:
        data = {}
        for i, c in  enumerate(info):
            data[i] = {
                "cve_id": c[1],
                "additional_links": c[2],
                "infomation": c[3],
                "cpe": c[4],
                "quality": c[5],
                "CVSS": c[6]
            }
    else:
        data = {
            "0":  {
                "cve_id": info[1],
                "additional_links": info[2],
                "information": info[3],
                "cpe": info[4],
                "quality": info[5],
                "CVSS": info[6]
            }
        }
    return data


async def get_data_by_ServiceName(service_name: str):
    service_name = service_name.lower().strip()
    try:
        conn = sqlite3.connect('vulners.db')
        cursor = conn.cursor()
        data = cursor.execute(
            f"""SELECT * FROM CVE WHERE cpeUri LIKE '%{service_name}%';""").fetchall()
        conn.close()
        if data is None:
            conn = sqlite3.connect('vulners.db')
            cursor = conn.cursor()
            data = cursor.execute(
                f"""SELECT * FROM CVE WHERE c AND description LIKE '%{service_name}%';""").fetchall()
            conn.close()
    except IndexError:
        return None

    data = await dataToJson(data)
    return data


async def get_data_from_CVE_ID( CVE_ID):
    conn = sqlite3.connect('vulners.db')
    cursor = conn.cursor()
    info = cursor.execute(f"SELECT * FROM CVE WHERE id=?", (CVE_ID,)).fetchall()[0]
    data = await dataToJson(info)
    conn.close()
    return data


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/check/')
def check_cve():
    requestData = request.args.get("host")
    isCVE = bool(requestData.__contains__("CVE-") and len(requestData.split("-")) == 3)
    if isCVE:
        data = asyncio.run(get_data_from_CVE_ID(requestData))
    else:
        data = asyncio.run(get_data_by_ServiceName(requestData))


    print(json.dumps(data))

    if len(data) > 0:
        return jsonify({"status": True, "code": 200, "cves": data})
    else:
        return jsonify({"status": False, "code": 400, "description": "CVE's not found"})


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5057, debug=True)
