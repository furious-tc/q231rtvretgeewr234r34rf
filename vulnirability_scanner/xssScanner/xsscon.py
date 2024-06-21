'''
XSSCon - 2019/2020
This project was created by menkrep1337 with 407Aex team. 
Copyright under the MIT license
'''
import argparse
import json
import time

from .lib.helper.helper import *
from .lib.helper.Log import *
from .lib.core import *
from random import randint
from .lib.crawler.crawler import *


def check():
	payload=int(6)
	payload=core.generate(payload)
			
	return payload

def clean_empty_keys(data):
    if isinstance(data, list):
        return [clean_empty_keys(item) for item in data if item and (isinstance(item, (dict, list)) and clean_empty_keys(item) or not isinstance(item, (dict, list)))]
    elif isinstance(data, dict):
        return {k: clean_empty_keys(v) for k, v in data.items() if v and (isinstance(v, (dict, list)) and clean_empty_keys(v) or not isinstance(v, (dict, list)))}
    else:
        return data

def xssScanStart(domain: str):
	qq = asyncio.run(Crawler.crawl(domain, 2, None, agent, core.generate(6), 2, '{"ID":"1094200543"}'))
	data = clean_empty_keys(qq)
	print(data)
	if len(data) > 0:
		return {"status": True, "code": 200, "xss": data}
	else:
		return {"status": False, "code": 400, "xss": []}


if __name__=="__main__":
	time_start = time.time()
	answer = xssScanStart("http://testphp.vulnweb.com/")

	print(answer)
	time_end = time.time()
	print(time_end - time_start)
