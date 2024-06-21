import asyncio
import json
import os
import re
import sqlite3
import time
from flask import Flask, request, jsonify
import asynsqlapi

app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/check/')
def check_cve():
    host = request.args.get('host')
    module = asynsqlapi.SqlModule(url=host, crawl_count=3)

    asyncio.run(module.main())

    if len(module.vulnerabilities) > 0:
        return jsonify({"status": True, "code": 200, "vulnerabilities": module.vulnerabilities})
    else:
        return jsonify({"status": False, "code": 400, "description": "SQLi not found"})


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5056, debug=True)
