import os
import logging.config
import configparser
import pymongo
import requests
from components.search_vulnerability import VulnerSearch
import pprint

_log_path = "logs/"
if not os.path.exists(_log_path):
    os.mkdir(_log_path, 0o755)
_setting_path = "settings/"
if not os.path.exists(_setting_path):
    os.mkdir(_setting_path, 0o755)

# read settings file
_path = "settings/settings_VulnerSearchModule.conf"
config = configparser.ConfigParser()
config.read(_path)

# create the logging file handler
_name_dir_log = "settings/log_VulnerSearchModule.conf"
logging.config.fileConfig(_name_dir_log)
log = logging.getLogger("VulnerSearchModule")

client = pymongo.MongoClient()
db = client[config.get("DATABASE_SCANNER", "BASE")]
coll = db[config.get("DATABASE_SCANNER", "COLLECTION")]


if __name__ == "__main__":
    result = coll.find_one({"ip": config.get("SETTING", "TARGET")})
    vuln_search = VulnerSearch()
    for port in result['result_scan']['tcp']:
        cpe = result['result_scan']['tcp'][str(port)]['cpe']
        product = result['result_scan']['tcp'][str(port)]['product'] + " " + \
                  result['result_scan']['tcp'][str(port)]['version']
        if len(cpe) > 0:
            print(cpe)
            res = vuln_search.search_circl(cpe=cpe)
            # res = search_circl(cpe=cpe)
            print(res)
            # print(cpe)
            # print(product)
    client.close()
