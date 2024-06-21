import asyncio
import json
import os
import re
import sqlite3
import time
from flask import Flask, request, jsonify
from xssScanner import xsscon

app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/check/')
def check_cve():
    host = request.args.get('host')
    answer = xsscon.xssScanStart(host)
    if answer["status"] is True:
        return jsonify(answer)
    elif answer["status"] is False:
        return jsonify({"status": False, "code": 400, "xss": [], "description": "XSS not found"})


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5055, debug=True)
