import random

import aiohttp
import asyncio

async def format_proxy(proxy_str):
    ip, port, username, password = proxy_str.split(':')
    return f"http://{username}:{password}@{ip}:{port}"

async def request(session, url, proxy):

    try:
        proxy = await format_proxy(proxy)
        async with session.get("http://" + url, proxy=proxy) as response:
            if response.status == 200:
                print(f"[+] Discovered URL ----> {url}")
    except aiohttp.ClientError:
        print("[-] Connection Error")
        pass

# Основная асинхронная функция
async def main(target_url, wordlist_file, proxy_list_file):
    # Загружаем прокси из файла
    with open(proxy_list_file, "r") as file:
        proxies = [line.strip() for line in file.readlines()]

    # Создаем сессию aiohttp
    async with aiohttp.ClientSession() as session:
        tasks = []
        with open(wordlist_file, "r") as wordlist:
            for line in wordlist:
                word = line.strip()
                test_url = target_url + "/" + word
                # Выбираем прокси по очереди
                for i in range(5):
                    proxy = random.choice(proxies)
                    tasks.append(request(session, test_url, proxy))
                    await asyncio.sleep(1)

        # Выполняем задачи асинхронно
        await asyncio.gather(*tasks)

# Запуск
target_url = "testphp.vulnweb.com"
wordlist_file = "common.txt"
proxy_list_file = "proxies.txt"

asyncio.run(main(target_url, wordlist_file, proxy_list_file))
