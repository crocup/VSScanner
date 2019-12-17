import datetime
import os
import logging.config
import configparser
import pymongo
import json
import requests
from components.search_vulnerability import VulnerSearch
from components.record_database import RecordMongo
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
    ip = config.get("SETTING", "TARGET")
    result = coll.find_one({"ip": ip})
    record_in_mongo = RecordMongo(db=config.get("DATABASE_SCANNER", "BASE"), coll=config.get("DATABASE_SCANNER", "COLLECTION"))
    for port in result['result_scan']['tcp']:
        cpe = result['result_scan']['tcp'][str(port)]['cpe']
        product = result['result_scan']['tcp'][str(port)]['product'] + " " + \
                  result['result_scan']['tcp'][str(port)]['version']
        vuln_search = VulnerSearch(cpe=cpe)
        if len(cpe) > 0:
            res = vuln_search.search_circl()
            print(res)
            now = datetime.datetime.now()
            record_in_mongo.database_vulner_search_tcp(ip=ip, time=now, port=port, cve=res)
    client.close()
    record_in_mongo.close_connection()
