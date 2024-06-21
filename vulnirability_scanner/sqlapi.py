import subprocess
from urllib.parse import urljoin
import requests
import time
import json
from bs4 import BeautifulSoup
from datetime import datetime

class SqlModule:

    def __init__(self, url, crawl_count, host='127.0.0.1', port='8075', adapter='wsgiref'):
        self.url = url
        self.crawl_count = crawl_count
        self.host = host
        self.port = port
        self.adapter = adapter
        self.base_url = f'http://{host}:{port}'
        self.visited = set()
        self.vulnerabilities = []

        # self.start_sqlmapapi()

    def main(self):
        links = self.getLinks(self.url)
        self.visited.update(links)
        for i in links:
            links = self.getLinks(i)
            self.visited.update(links)
        [self.scan(link) for link in self.visited]
        print(datetime.now() - time1)

    def scan(self, url):
        task_info = self.create_task()
        taskid = task_info.get('taskid')
        print("New Task ID:", taskid)
        print("url:", url, '\n')
        start_info = self.start_scan(taskid, url)
        print("Start Scan Info:", start_info)
        time.sleep(5)
        scan_data = self.get_scan_data(taskid)
        self.vulnerabilities.append(scan_data)
        print(json.dumps(scan_data, indent=2))

    def start_sqlmapapi(self):
        try:
            subprocess.Popen(
                ['python', './sqlmap-dev/sqlmapapi.py', '-s', f'-H {self.host}', f'-p {self.port}', f'--adapter={self.adapter}']
            )
        except Exception as e:
            print("An error occurred while starting sqlmapapi:", str(e))

    def check_version(self):
        response = requests.get(f'{self.base_url}/version')
        if response.status_code == 200:
            return response.json()

    def create_task(self):
        response = requests.get(f'{self.base_url}/task/new')
        if response.status_code == 200:
            return response.json()

    def start_scan(self, taskid, url):
        payload = {
            "url": url,
            "options": {
                "forms": True,
                "crawl": 10,
                "level": 5,
                "risk": 3,
                "threads": 10,
                "timeout": 1
            }
        }
        response = requests.post(f'{self.base_url}/scan/{taskid}/start', json=payload)
        if response.status_code == 200:
            return response.json()
        else:
            print("Failed to start_scan, status code:", response.status_code)
            print("Response text:", response.text)

    def list_options(self, taskid):
        response = requests.get(f'{self.base_url}/scan/{taskid}/list')
        if response.status_code == 200:
            return response.json()
        else:
            print("Failed to list_options, status code:", response.status_code)
            print("Response text:", response.text)

    def check_status(self, taskid):
        response = requests.get(f'{self.base_url}/scan/{taskid}/status')
        if response.status_code == 200:
            return response.json()

    def get_scan_data(self, taskid):
        response = requests.get(f'{self.base_url}/scan/{taskid}/data')
        if response.status_code == 200:
            return response.json()
        else:
            print("Failed to get_scan_data, status code:", response.status_code)
            print("Response text:", response.text)

    def get_log(self, taskid):
        response = requests.get(f'{self.base_url}/scan/{taskid}/log')
        if response.status_code == 200:
            return response.json()

    def stop_scan(self, taskid):
        response = requests.get(f'{self.base_url}/scan/{taskid}/stop')
        return response.json()

    def kill_scan(self, taskid):
        response = requests.get(f'{self.base_url}/scan/{taskid}/kill')
        return response.json()

    def delete_task(self, taskid):
        response = requests.get(f'{self.base_url}/task/{taskid}/delete')
        return response.json()

    def getLinks(self, url):
        links = []

        conn = requests.session()
        text = conn.get(url).text
        isi = BeautifulSoup(text, "html.parser")

        for obj in isi.find_all("a", href=True):
            url = obj["href"]

            if url.startswith("http://") or url.startswith("https://"):
                continue

            elif url.startswith("mailto:") or url.startswith("javascript:"):
                continue

            elif urljoin(self.url, url) in links:
                continue

            else:
                links.append(urljoin(self.url, url))

        return links


if __name__ == "__main__":
    time1 = datetime.now()
    SqlModule(url='http://testphp.vulnweb.com', crawl_count=3).main()
