import json
from argparse import ArgumentParser
import configparser
from components.search_vulnerability import VulnerabilitySearch
from datetime import datetime

# read settings file
path = "settings/settings.conf"
config = configparser.ConfigParser()
config.read(path)


def result(json_str):
    """
    result request
    :param json_str: json
    :return: None
    """
    print("[+] --- Result:")
    print(json_str)


def main():
    parser = ArgumentParser()
    parser.add_argument("-p", "--product",
                        metavar="PRODUCT")
    parser.add_argument("-v", "--version",
                        metavar="VERSION")
    parser.add_argument("-c", "--cpe",
                        metavar="CPE")
    parser.add_argument("-e", "--cve",
                        help="example: python vsscanner.py -v CVE-2017-14174",
                        metavar="CVE")
    parser.add_argument("-d", "--database",
                        help="example: python vsscanner.py -d nginx",
                        metavar="DATABASE")
    args = parser.parse_args()
    vulnerabilities_api = VulnerabilitySearch(vulners_api=config.get("VULNERS", "API"))
    print("[+] --- {} --- Program start".format(datetime.now().strftime("%H:%M:%S")))
    if args.cpe is not None:
        vulnerabilities_exploit_list_cpe = vulnerabilities_api.get_vulnerabilities_by_cpe(cpe=args.cpe)
        json_str = json.dumps(vulnerabilities_exploit_list_cpe, indent=4)
        result(json_str)
    elif args.database is not None:
        vulnerabilities_database = vulnerabilities_api.search_database(product=args.database)
        json_str = json.dumps(vulnerabilities_database, indent=4)
        result(json_str)
    elif args.product is not None and args.version:
        vulnerabilities_exploit_list_software = vulnerabilities_api.get_vulnerabilities_by_software(name=args.product, version=args.version)
        json_str = json.dumps(vulnerabilities_exploit_list_software, indent=4)
        result(json_str)
    elif args.cve is not None:
        vulnerabilities_cve = vulnerabilities_api.get_cve(cve=args.cve)
        json_str = json.dumps(vulnerabilities_cve, indent=4)
        result(json_str)
    else:
        print("[+] --- Error")
    print("[+] --- {} --- Program stop".format(datetime.now().strftime("%H:%M:%S")))


if __name__ == "__main__":
    main()
