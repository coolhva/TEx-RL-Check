#!/usr/bin/env python

""" Determine which IOC's are blocked by Broadcom already to understand which
IOC's need to be added to the policy to avoid large custom policies.

The input CSV file needs to contain the field Indicator and ThreatType for this
script to function!

Installation:

  1. Create virtual env: python -m venv venv
  2. Activate venv
  3. Install requirements (pip install -r requirements.txt)
  4. create .env file with TEX_API_KEY key that holds the API key
  5. Create output folder (mkdir output)
  6. Run, with venv activated, python rlcheckmt.py <inputfile>
  7. See on screen updates and output in output folder.

"""
__author__ = "Henk van Achterberg, PM Threat Intelligence, Broadcom"
__copyright__ = "Copyright 2021, Henk van Achterberg"
__credits__ = ["Henk van Achterberg"]
__license__ = "GPL"
__version__ = "0.9"
__maintainer__ = "Henk van Achterberg"
__email__ = "henk.vanachterberg@broadcom.com"
__status__ = "Development"

import sys
import os
import optparse
import csv
import datetime
import dotenv
import requests
import queue
import threading

# ------------------------ Application variables ---------------------------- #

# Use dotenv to save the API key in ".env" file under the key TEX_API_KEY
# Example .env file:
# TEX_API_KEY = 201002467ae044f6-99b9b747d23659838b125fa28a984b118f268468c5ce76817e1d3b999ec942ce

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
dotenv.load_dotenv(dotenv_path)

TEX_API_KEY = os.environ.get("TEX_API_KEY")

# Threat types that are supported to look up with the API, non supported
# threat types will go in to the error file.
SUPPORTED_THREAT_TYPES = ['IP Address', 'Domain', 'URL']

# Minimum threat level blocked in the WSS/ProxySG policy
MIN_BLOCKED_RISK_LEVEL = 8

# Categories that ar blocked by the policy, categories below for reference
BLOCKED_CATEGORY_IDS = [17, 18, 43, 44]

# Categories:
# id name
# 1 Adult/Mature Content
# 3 Pornography
# 4 Sex Education
# 5 Intimate Apparel/Swimsuit
# 6 Nudity
# 7 Gore/Extreme
# 9 Scam/Questionable Legality
# 11 Gambling
# 14 Violence/Intolerance
# 15 Weapons
# 16 Abortion
# 17 Hacking
# 18 Phishing
# 20 Entertainment
# 21 Business/Economy
# 22 Alternative Spirituality/Belief
# 23 Alcohol
# 24 Tobacco
# 25 Controlled Substances
# 26 Child Pornography
# 27 Education
# 29 Charitable/Non-Profit
# 30 Art/Culture
# 31 Finance
# 32 Brokerage/Trading
# 33 Games
# 34 Government/Legal
# 35 Military
# 36 Political/Social Advocacy
# 37 Health
# 38 Technology/Internet
# 40 Search Engines/Portals
# 43 Malicious Sources/Malnets
# 44 Malicious Outbound Data/Botnets
# 45 Job Search/Careers
# 46 News
# 47 Personals/Dating
# 49 Reference
# 50 Mixed Content/Potentially Adult
# 51 Chat (IM)/SMS
# 52 Email
# 53 Newsgroups/Forums
# 54 Religion
# 55 Social Networking
# 56 File Storage/Sharing
# 57 Remote Access
# 58 Shopping
# 59 Auctions
# 60 Real Estate
# 61 Society/Daily Living
# 63 Personal Sites
# 64 Restaurants/Food
# 65 Sports/Recreation
# 66 Travel
# 67 Vehicles
# 68 Humor/Jokes
# 71 Software Downloads
# 83 Peer-to-Peer (P2P)
# 84 Audio/Video Clips
# 85 Office/Business Applications
# 86 Proxy Avoidance
# 87 For Kids
# 88 Web Ads/Analytics
# 89 Web Hosting
# 90 Uncategorized
# 92 Suspicious
# 93 Sexual Expression
# 95 Translation
# 96 Web Infrastructure
# 97 Content Delivery Networks
# 98 Placeholders
# 101 Spam
# 102 Potentially Unwanted Software
# 103 Dynamic DNS Host
# 106 E-Card/Invitations
# 107 Informational
# 108 Computer/Information Security
# 109 Internet Connected Devices
# 110 Internet Telephony
# 111 Online Meetings
# 112 Media Sharing
# 113 Radio/Audio Streams
# 114 TV/Video Streams
# 118 Piracy/Copyright Concerns
# 121 Marijuana

# ----------------------------- Helper classes ------------------------------ #


class CSVWriter:
    """Write CSV files trough a queue"""

    def __init__(self, *args):
        self.filewriter = open(args[0], args[2],
                               newline='', encoding="utf-8-sig")
        self.csvwriter = csv.DictWriter(self.filewriter, fieldnames=args[1],
                                        dialect='excel', delimiter=";")
        self.csvwriter.writeheader()
        self.queue = queue.Queue()
        self.finished = False
        threading.Thread(name="CSVWriter", target=self.internal_writer).start()

    def write(self, data):
        self.queue.put(data)

    def internal_writer(self):
        while not self.finished:
            try:
                data = self.queue.get(True, 1)
                self.csvwriter.writerow(data)
                self.queue.task_done()
            except queue.Empty:
                continue

    def close(self):
        self.queue.join()
        self.finished = True
        self.filewriter.close()


class IOCStat:
    def __init__(self, *args):
        self.ioc_blocked = 0
        self.ioc_policy = 0
        self.ioc_error = 0
        self.ioc_total = 0
        self.queue = queue.Queue()
        self.update_interval = args[0]
        self.lastoutput = (datetime.datetime.now() -
                           datetime.timedelta(seconds=60))
        self.finished = False
        threading.Thread(name="IOCStat", target=self.stat_keeper).start()

    def update(self, data):
        self.queue.put(data)

    def stats(self):
        ret = dict()
        ret['ioc_total'] = self.ioc_total
        ret['ioc_blocked'] = self.ioc_blocked
        ret['ioc_policy'] = self.ioc_policy
        ret['ioc_error'] = self.ioc_error
        return ret

    def stat_keeper(self):
        while not self.finished:
            try:
                if (datetime.datetime.now() -
                   self.lastoutput).total_seconds() > self.update_interval:
                    self.lastoutput = datetime.datetime.now()
                    sys.stdout.write(f"\r[{self.lastoutput}] "
                                     f"Processed: {self.ioc_total}, "
                                     f"Blocked: {self.ioc_blocked}, "
                                     f"Policy: {self.ioc_policy}, "
                                     f"Error: {self.ioc_error}")
                    sys.stdout.flush()

                data = self.queue.get(True, 1)
                if data['type'] == 'blocked':
                    self.ioc_blocked += 1
                elif data['type'] == 'policy':
                    self.ioc_policy += 1
                elif data['type'] == 'error':
                    self.ioc_error += 1
                self.ioc_total += 1
                self.queue.task_done()
            except queue.Empty:
                continue

    def close(self):
        self.queue.join()
        self.finished = True


def log(message):
    ts = datetime.datetime.now()
    print(f"[{ts}] {message}")


# Initialize multi threading variables and the queue used for the IOC's
num_worker_threads = 0
status_update_interval = 0
q = queue.Queue()
threads = []


def rlcheck(ioc):
    """Return risklevel, categories and if it is blocked by policy"""

    # Set authentication based on value in .env file.
    auth_headers = {'Authorization': TEX_API_KEY}
    tex_api_url = 'https://threatexplorer.symantec.com/api/v1/url' + \
                  '?level=STANDARD&url='
    # Initialize return object
    ret = dict()
    ret['error'] = 0
    ret['blocked'] = 0
    ret['risklevel'] = 0
    ret['category'] = []

    try:
        response = requests.get(tex_api_url + ioc, headers=auth_headers)
    except requests.exceptions.RequestException as e:
        ret['error'] = e

    if (response.status_code == 200):
        ret['error'] = 0
        ret['blocked'] = 0
        ret['category'] = []
        data = response.json()

        if "categorization" in data and "categories" in data["categorization"]:
            categories = data["categorization"]["categories"]

            for cat in categories:
                ret['category'].append(cat["name"])
                if (cat["id"] in BLOCKED_CATEGORY_IDS):
                    ret['blocked'] = 1
                    ret['blocked_by_cat'] = 1

        if "threatRiskLevel" in data and "level" in data["threatRiskLevel"]:
            level = data["threatRiskLevel"]["level"]
            ret['risklevel'] = level

            if level >= MIN_BLOCKED_RISK_LEVEL:
                ret['blocked'] = 1
                ret['blocked_by_rl'] = 1

    elif response.status_code == 400:
        ret['error'] = 400
    elif response.status_code == 401:
        ret['error'] = 401
    elif response.status_code == 429:
        ret['error'] = 429

    return ret


def do_work(item, csv_blocked, csv_policy, csv_error, stat):
    """Look up IOC, augment with api data and write it to the correct file"""

    ret = rlcheck(item["Indicator"])
    categories = ""
    if ret['error'] != 0:
        log(f"Error {ret['error']} while processing {item['Indicator']}")
        stat.update({'type': 'error'})
        csv_error.write(item)
    else:
        for cat in ret['category']:
            if categories == "":
                categories = cat
            else:
                categories += ', ' + cat
        item.update({'BC_RiskLevel': ret['risklevel'],
                    'BC_Category': categories})
        if ret['blocked'] == 1:
            csv_blocked.write(item)
            stat.update({'type': 'blocked'})
        else:
            csv_policy.write(item)
            stat.update({'type': 'policy'})


def worker(shutdown_event, csv_blocked, csv_policy, csv_error, stat):
    """Process IOC from queue and start processing them"""
    while not shutdown_event.is_set():
        try:
            item = q.get(block=True, timeout=0.05)
            do_work(item, csv_blocked, csv_policy, csv_error, stat)
            q.task_done()
        except queue.Empty:
            continue


def main(argv=sys.argv):
    p = optparse.OptionParser(
        description='Check risk level for URL, IP and ' +
        'Domain to exclude already blocked items in the Proxy/WSS Policy',
        prog='rlcheck',
        version='0.9',
        usage='%prog <input file>')
    p.add_option('--output-dir', '-f', dest="out", help="Output directory")
    p.set_default("out", "output")
    p.add_option('--threads', '-t', dest="threads", help="Concurrent threads")
    p.set_default("threads", 10)
    p.add_option('--interval', '-i', dest="interval", help="Update interval")
    p.set_default("interval", 5)

    options, arguments = p.parse_args()

    if len(arguments) != 1:
        p.error("Incorrect arguments")

    num_worker_threads = int(options.threads)
    status_update_interval = int(options.interval)

    # Check for inputfile
    fname = arguments[0]
    if not os.path.exists(fname):
        sys.exit("Invalid input file")

    # set output directory and set filenames
    if options.out != 'output':
        outpath = options.out
    else:
        outpath = os.path.join(os.getcwd(), options.out)

    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    outputfile_blocked = os.path.join(
        outpath, ts + '_blocked' + '_' + os.path.basename(fname))
    outputfile_policy = os.path.join(
        outpath, ts + '_policy' + '_' + os.path.basename(fname))
    outputfile_error = os.path.join(
        outpath, ts + '_error' + '_' + os.path.basename(fname))

    # Get fieldnames from inputfile and add api return fields
    with open(fname, encoding='utf-8-sig') as csv_file:
        csv_reader = csv.DictReader(csv_file)

        for row in csv_reader:
            fieldnames = row
            fieldnames.update({'BC_RiskLevel': '',
                               'BC_Category': ''})
            break
        # go to begining of file to count IOC's (minus header)
        csv_file.seek(0)
        ioccount = len(list(csv_reader)) - 1

    log(f"Checking {ioccount} IOC's in {fname} "
        f"with {num_worker_threads} threads...")

    # Create threading save outputfile writers
    csv_blocked = CSVWriter(outputfile_blocked, fieldnames, "w")
    csv_policy = CSVWriter(outputfile_policy, fieldnames, "w")
    csv_error = CSVWriter(outputfile_error, fieldnames, "w")
    stat = IOCStat(status_update_interval)

    shutdown_event = threading.Event()

    # Create worker threads
    for i in range(num_worker_threads):
        t = threading.Thread(target=worker, args=(shutdown_event,
                                                  csv_blocked,
                                                  csv_policy,
                                                  csv_error,
                                                  stat))
        t.start()
        threads.append(t)

    # Open source file and add rows to the queue
    with open(fname) as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            if row['ThreatType'] in SUPPORTED_THREAT_TYPES:
                q.put(row)
            else:
                csv_error.write(row)
                stat.update({'type': 'error'})

    # Wait for all the items in the queue to be processed
    q.join()

    # Shutdown threads and close files
    shutdown_event.set()
    csv_blocked.close()
    csv_policy.close()
    csv_error.close()

    # Create end of line because of the status line
    print("")

    log(f"Total: {stat.stats()['ioc_total']}, "
        f"Blocked: {stat.stats()['ioc_blocked']}, "
        f"Policy: {stat.stats()['ioc_policy']}, "
        f"Error: {stat.stats()['ioc_error']}")

    # Close statistics thread
    stat.close()

    if threading.active_count() > 1:
        log("Waiting for threads to finish...")
    while threading.active_count() > 1:
        continue
    log("Finished")


if __name__ == '__main__':
    main()
