import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ProcessPoolExecutor, as_completed

from ..helper.Log import *
from ..helper.helper import *
from ..core import *


class Crawler:
    XSS_PARSED = []
    visited = []

    @classmethod
    async def get_links(cls, base, proxy, headers, cookie):
        lst = []

        # Обработка cookies, чтобы они были в правильном формате
        if not isinstance(cookie, dict):
            cookie = {}  # или преобразовать cookie в словарь, если это необходимо

        try:
            async with aiohttp.ClientSession(headers=headers, cookies=cookie) as conn:
                async with conn.get(base, proxy=proxy) as response:
                    text = await response.text()
        except Exception as e:
            print(f"Failed to fetch {base}: {e}")
            return lst

        isi = BeautifulSoup(text, "html.parser")

        for obj in isi.find_all("a", href=True):
            url = obj["href"]

            if url.startswith("http://") or url.startswith("https://"):
                continue

            elif url.startswith("mailto:") or url.startswith("javascript:"):
                continue

            elif urljoin(base, url) in cls.visited:
                continue

            else:
                lst.append(urljoin(base, url))
                cls.visited.append(urljoin(base, url))

        return lst

    @classmethod
    async def crawl(cls, base, depth, proxy, headers, level, method, cookie):
        if depth <= 0:
            return

        urls = await cls.get_links(base, proxy, headers, cookie)

        loop = asyncio.get_running_loop()
        with ProcessPoolExecutor(max_workers=7) as executor:
            tasks = [loop.run_in_executor(executor, cls.run_main, url, proxy, headers, level, cookie, method) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    print(f'Error: {result}')
                else:
                    cls.XSS_PARSED.append(result)

        await asyncio.gather(*[cls.crawl(url, depth - 1, proxy, headers, level, method, cookie) for url in urls])

        return cls.XSS_PARSED

    @staticmethod
    def run_main(url, proxy, headers, level, cookie, method):
        return core.main(url, proxy, headers, level, cookie, method)


# Пример использования:
# asyncio.run(Crawler.crawl('http://example.com', 2, None, {}, 0, 'GET', {}))
