#!/usr/bin/python

# Import local modules/packages
from classes.colors import bcolors
import csv

# Import 3rd party packages
import requests
from argparse import ArgumentParser
import shodan

api = shodan.Shodan('yXfN7k2pCzeUj9YkKnIaSosLoQnjQfFe')
parser = ArgumentParser(
    description='A script to check out some wacky urls :) ',
    epilog='Try it out!'
)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-f', '--file', dest='myFile', help='Import a list from the specified file')
group.add_argument('-u', '--url', dest='myUrl', help='Check the specified URL')
group.add_argument('-l', '--list', dest='myList', nargs='+', help='Upload a list')
group.add_argument('-i', '--ip', dest='myIP', help='Search Shodan for a specific IP')
args = parser.parse_args()
myFile = args.myFile
myUrl = args.myUrl
myList = args.myList
myIP = str(args.myIP)
bad = [503, 500, 400, 403, 404, 401, 502, 511]


def test_urls(url):
    try:
        rs = requests.get('https://' + str(url), stream=True)
        r = requests.get('http://' + str(url), stream=True)
        ip_add = r.raw._connection.sock.getpeername()
        if rs.status_code in bad:
            print(bcolors.FAIL + 'https://' + str(url) + "  " + str(rs.status_code) + bcolors.ENDC)
            print(ip_add)
        else:
            print(bcolors.OKGREEN + 'https://' + str(url) + "  " + str(rs.status_code) + bcolors.ENDC)
            print(ip_add)
        if r.status_code in bad:
            print(bcolors.FAIL + 'http://' + str(url) + "  " + str(r.status_code) + bcolors.ENDC)
            print(ip_add)
        else:
            print('http://' + str(url) + " " + str(r.status_code) + bcolors.ENDC)
            print(ip_add)
    except requests.exceptions.ConnectionError:
        print(bcolors.WARNING + "Failed to connect to " + url + bcolors.ENDC)


def sshodan_link(link):
    try:
        # Search Shodan
        results = api.search(link)
        # Show the results
        print('Results found: {}'.format(results['total']))
        for result in results['matches']:
            host = api.host(result['ip_str'])
            print("""IP: {}
                Organization: {}
                Operating System: {}
                Host Names: {}
                City: {}
                Region Code: {}
                Country Name: {}
                Vulns: {}
                """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'), host.get('city', 'n/a'),
                           host.get('region_code', 'n/a'), host.get('country_name', 'n/a'),
                           host.get('hostnames', 'n/a'), host.get('vulns', 'n/a')))
            # print(result['data'])
            print('')
    except shodan.APIError:
        print('Error: {}'.format(shodan.APIError))


def sshodan_host(ipaddr):
    try:
        host = api.host(ipaddr)
        print("""
                IP: {}
                Organization: {}
                Operating System: {}
                Host Names: {}
                City: {}
                Region Code: {}
                Country Name: {}
                Vulns: {}

        """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'), host.get('city', 'n/a'),
                   host.get('region_code', 'n/a'), host.get('country_name', 'n/a'), host.get('hostnames', 'n/a'),
                   host.get('vulns', 'n/a')))
    except shodan.APIError:
        print('Error: {}'.format(shodan.APIError))


if myUrl is not None:
    test_urls(myUrl)
    sshodan_link(myUrl)
else:
    pass

if myFile is not None:
    urlList = []
    with open(myFile, encoding='utf-8-sig') as csv_file:
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:
            urlList.extend(row)

        for urls in urlList:
            print(urls)
            test_urls(urls)

        for urls in urlList:
            sshodan_link(urls)

if myList is not None:
    for urls in myList:
        test_urls(urls)
        sshodan_link(urls)

if myIP is not None:
    sshodan_host(myIP)
