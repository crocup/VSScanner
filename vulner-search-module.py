import datetime
import os
import logging.config
import configparser
import pymongo
from components.search_vulnerability import VulnerSearch
from components.record_database import RecordMongo

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


def find_status(product):
    """

    :param product:
    :return:
    """
    products = str(product).split()
    products = products[0].lower()
    if products in cpe:
        status = True
    else:
        status = False
    return status


if __name__ == "__main__":
    ip = config.get("SETTING", "TARGET")
    result = coll.find_one({"ip": ip})
    record_in_mongo = RecordMongo(db=config.get("DATABASE_SCANNER", "BASE"),
                                  coll=config.get("DATABASE_SCANNER", "COLLECTION"))
    for port in result['result_scan']['tcp']:
        cpe = result['result_scan']['tcp'][str(port)]['cpe']
        product = result['result_scan']['tcp'][str(port)]['product']
        version = result['result_scan']['tcp'][str(port)]['version']
        product_version = product + " " + version
        if len(cpe) > 0:
            bool_cpe = find_status(product)
            now = datetime.datetime.now()
            vulner_search = VulnerSearch(cpe=cpe, vulners_api=config.get("VULNERS", "API"))
            vulnerabilities_cve_list = vulner_search.search_circl(status=bool_cpe)
            vulnerabilities_exploit_list = vulner_search.search_vulners(status=bool_cpe,
                                                                        product_version=product_version)
            record_in_mongo.database_vulner_search_tcp(ip=ip, time=now, port=port,
                                                       cve=vulnerabilities_cve_list,
                                                       exploit=vulnerabilities_exploit_list)
    client.close()
    record_in_mongo.close_connection()
