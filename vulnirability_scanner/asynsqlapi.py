import asyncio
import random

import aiohttp
from aiohttp import ClientSession
from urllib.parse import urljoin
import requests
import time
import json
from bs4 import BeautifulSoup
from datetime import datetime
import concurrent.futures


class SqlModule:

    def __init__(self, url, crawl_count, host='127.0.0.1', port='8075', adapter='wsgiref'):
        # self.proxies = asyncio.run(self.convert_proxies("proxies.txt"))
        #print(self.proxies)
        self.url = url
        self.crawl_count = crawl_count
        self.host = host
        self.port = port
        self.adapter = adapter
        self.base_url = f'http://{host}:{port}'
        self.visited = set()
        self.vulnerabilities = []

    async def convert_proxies(self, file_path):
        http_proxies = []
        with open(file_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                ip, port, username, password = line.strip().split(':')
                http_proxy = f"http://{username}:{password}@{ip}:{port}"
                http_proxies.append(http_proxy)
        return http_proxies

    async def main(self):
        async with ClientSession() as session:
            links = await self.getLinks(session, self.url)
            self.visited.update(links)
            for i in links:
                sub_links = await self.getLinks(session, i)
                self.visited.update(sub_links)

            tasks = [self.scan(session, link) for link in self.visited]
            await asyncio.gather(*tasks)


    async def scan(self, session, url):
        task_info = await self.create_task(session)
        taskid = task_info.get('taskid')
       # print("New Task ID:", taskid)
       # print("url:", url, '\n')
        start_info = await self.start_scan(session, taskid, url)
        #print("Start Scan Info:", start_info)
        await asyncio.sleep(3)
        scan_data = await self.get_scan_data(session, taskid)
        if len(scan_data.get("data")) > 0:
            elements: dict = random.choice(list(scan_data["data"][1]["value"][0]["data"].values()))
            content = {
                "scanned_url": url,
                "title": elements["title"],
                "payload": elements["payload"],
                "matchRatio": elements["matchRatio"],
            }
            self.vulnerabilities.append(content)
       # print(json.dumps(scan_data, indent=2))

    async def request_with_retries(self, session, url, method='GET', json_data=None, retries=3, backoff_factor=1):
        for attempt in range(retries):
            try:
                async with session.request(method, url, json=json_data) as response:
                    response.raise_for_status()
                    return await response.json()
            except (aiohttp.ClientError, aiohttp.http_exceptions.HttpProcessingError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(backoff_factor * (2 ** attempt))
                else:
                    print(f"Request to {url} failed after {retries} attempts")
                    raise e

    async def create_task(self, session):
        url = f'{self.base_url}/task/new'
        return await self.request_with_retries(session, url)

    async def start_scan(self, session, taskid, url):
        payload = {
            "url": url,
            "options": {
                "forms": True,
                "crawl": 10,
                "level": 5,
                "risk": 3,
                "threads": 10,
                "timeout": 1,
                # "proxy": random.choice(self.proxies)

            }
        }
        url = f'{self.base_url}/scan/{taskid}/start'
        return await self.request_with_retries(session, url, method='POST', json_data=payload)

    async def get_scan_data(self, session, taskid):
        url = f'{self.base_url}/scan/{taskid}/data'
        return await self.request_with_retries(session, url)

    async def getLinks(self, session, url):
        links = []

        async with session.get(url) as response:
            text = await response.text()
            soup = BeautifulSoup(text, "html.parser")

            for obj in soup.find_all("a", href=True):
                link = obj["href"]

                if link.startswith("http://") or link.startswith("https://"):
                    continue

                elif link.startswith("mailto:") or link.startswith("javascript:"):
                    continue

                full_url = urljoin(self.url, link)
                if full_url in links:
                    continue
                else:
                    links.append(full_url)

        return links


if __name__ == "__main__":
    time1 = datetime.now()
    module = SqlModule(url='http://testphp.vulnweb.com', crawl_count=3)

    asyncio.run(module.main())

    print(json.dumps(module.vulnerabilities, indent=2))
