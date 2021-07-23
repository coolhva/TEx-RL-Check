#!/usr/bin/env python
import sys
import os
import optparse
import csv
import datetime
import dotenv
import requests

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
dotenv.load_dotenv(dotenv_path)

TEX_API_KEY = os.environ.get("TEX_API_KEY")
SUPPORTED_THREAT_TYPES = ['IP Address', 'Domain', 'URL']
MIN_BLOCKED_RISK_LEVEL = 8

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

BLOCKED_CATEGORY_IDS = [17, 18, 43, 44]


def rlcheck(ioc):
    auth_headers = {'Authorization': TEX_API_KEY}
    tex_api_url = 'https://threatexplorer.symantec.com/api/v1/url' + \
                  '?level=STANDARD&url='
    response = requests.get(tex_api_url + ioc, headers=auth_headers)

    ret = dict()

    if (response.status_code == 200):
        ret['error'] = 0
        ret['blocked'] = 0
        ret['category'] = []
        data = response.json()

        if "categorization" in data and "categories" in data["categorization"]:
            categories = data["categorization"]["categories"]

            for cat in categories:
                ret['category'].append(cat["id"])
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
        print("Parameter error")
        ret['error'] = 400
    elif response.status_code == 401:
        print("Unauthorized")
        ret['error'] = 401
    elif response.status_code == 429:
        print("API Limit reached")
        ret['error'] = 429

    return ret


def main(argv=sys.argv):
    p = optparse.OptionParser(
        description='Check risk level for URL, IP and \
            Domain to exclude already blocked items in the Proxy/WSS Policy',
        prog='rlcheck',
        version='0.1',
        usage='%prog <input file>')
    p.add_option('--output-dir', '-f', dest="out", help="Output directory")
    p.set_default("out", "output")

    options, arguments = p.parse_args()

    if len(arguments) != 1:
        p.error("Incorrect arguments")

    fname = arguments[0]
    if not os.path.exists(fname):
        sys.exit("Invalid input file")

    if options.out != 'output':
        outpath = options.out
    else:
        outpath = os.path.join(os.getcwd(), options.out)

    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    outputfile_blocked = os.path.join(
        outpath, ts + '_' + os.path.basename(fname) + '_blocked')
    outputfile_policy = os.path.join(
        outpath, ts + '_' + os.path.basename(fname) + '_policy')
    outputfile_error = os.path.join(
        outpath, ts + '_' + os.path.basename(fname) + '_error')

    with open(fname) as csv_file, \
            open(outputfile_blocked, "w") as output_blocked, \
            open(outputfile_policy, "w") as output_policy, \
            open(outputfile_error, "w") as output_error:
        csv_reader = csv.DictReader(csv_file)
        line_count = 0
        blocked_count = 0
        policy_count = 0
        error_count = 0

        for row in csv_reader:
            if line_count == 0:
                csv_blocked = csv.DictWriter(output_blocked, fieldnames=row)
                csv_blocked.writeheader()
                csv_policy = csv.DictWriter(output_policy, fieldnames=row)
                csv_policy.writeheader()
                csv_error = csv.DictWriter(output_error, fieldnames=row)
                csv_error.writeheader()
                line_count += 1

            if row['ThreatType'] in SUPPORTED_THREAT_TYPES:
                print(f'{row["ThreatType"]}: {row["Indicator"]}')
                ret = rlcheck(row["Indicator"])
                if ret['error'] == 0 and ret['blocked'] == 1:
                    print(f'Blocked: {ret["blocked"]}, RL: {ret["risklevel"]}')
                    csv_blocked.writerow(row)
                    blocked_count += 1
                elif ret['error'] == 0 and ret['blocked'] == 0:
                    print(f'Blocked: {ret["blocked"]}, RL: {ret["risklevel"]}')
                    csv_policy.writerow(row)
                    policy_count += 1
                elif ret['error'] != 0:
                    print(f'Error: {ret["error"]}')
                    csv_error.writerow(row)
                    error_count += 1

    if blocked_count == 0:
        os.remove(outputfile_blocked)

    if policy_count == 0:
        os.remove(outputfile_policy)

    if error_count == 0:
        os.remove(outputfile_error)

    print(f'Blocked: { blocked_count}, Policy: { policy_count }' +
          f', Error { error_count}')


if __name__ == '__main__':
    main()
