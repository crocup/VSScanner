# VSScanner (Vulnerability Service Scanner) ver 0.0.1

## About
Getting data from the resource https://vulners.com

## Usage
vsscanner.py [-h] [-p PRODUCT] [-v VERSION] [-c CPE] [-e CVE]
                    [-d DATABASE]

## Example
python vsscanner.py -e CVE-2017-14174
                    
# Dependency Installation
1. Virtual environment setup: 
- sudo apt-get install python3-pip
- sudo pip3 install virtualenv 
- virtualenv venv
2. Source venv/bin/activate
3. pip install -r requirements.txt
