import datetime
import os
import logging.config
import configparser
import pymongo
from components.search_vulnerability import VulnerabilitySearch, search_circl
from components.record_database import RecordMongo

_log_path = "logs/"
if not os.path.exists(_log_path):
    os.mkdir(_log_path)
_setting_path = "settings/"
if not os.path.exists(_setting_path):
    os.mkdir(_setting_path)

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
    record_in_mongo = RecordMongo(db=config.get("DATABASE_SCANNER", "BASE"),
                                  coll=config.get("DATABASE_SCANNER", "COLLECTION"))
    vulnerabilities_api = VulnerabilitySearch(vulners_api=config.get("VULNERS", "API"))
    for port in result['result_scan']['tcp']:
        cpe = result['result_scan']['tcp'][str(port)]['cpe']
        product = result['result_scan']['tcp'][str(port)]['product']
        version = result['result_scan']['tcp'][str(port)]['version']
        # Get now data
        now = datetime.datetime.now()
        # get CVE
        vulnerabilities_cve_list = search_circl(cpe=cpe)
        # Get vulnerabilities and exploits by software name and version
        vulnerabilities_exploit_list_software = vulnerabilities_api.get_vulnerabilities_by_software(name=product,
                                                                                                    version=version)
        # Get vulnerabilities by CPE product and version string
        vulnerabilities_exploit_list_cpe = vulnerabilities_api.get_vulnerabilities_by_cpe(cpe=cpe)
        record_in_mongo.database_vulner_search_tcp(ip=ip, time=now, port=port,
                                                   cve=vulnerabilities_cve_list,
                                                   exploit_software=vulnerabilities_exploit_list_software,
                                                   exploit_cpe=vulnerabilities_exploit_list_cpe)
    client.close()
    record_in_mongo.close_connection()
