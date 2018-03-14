#!/usr/bin/env python

# Acknowledgements
#
# This tool is a modified version of github.com/0x4D31/burpa to work with StackStorm automation and Docker.

import argparse
import os
import sys
import tempfile
import time
import re
import requests

# stackstorm action runner module
from st2actions.runners.pythonrunner import Action

# grab Burp container IP
network_file = open("/opt/stackstorm/common/networks.txt", "r")  # /common is a shared volume between Docker containers
data = network_file.readlines()
BURP_IP = ''
for line in data:
    if re.search('BURP_IP', line):
        BURP_IP = re.sub('BURP_IP=', '', line)
BURP_IP = BURP_IP.replace('\n', '')
network_file.close()

api_port = "8090"                   # default api port
proxy_url = "http://" + BURP_IP     # default Burp proxy URL (localhost of Burp container)
proxy_port = "8080"         # default proxy port

class Burp_Scan(Action):
    def run(self, url):
        print("Parsed URL = {}".format(url))
        target_url = url

        # adding target to scope
        print("[+] Adding target url to scope ...")
        add_scope(target_url)

        """
        Need better way to know when spider queue = 0.
        Currently, just waiting a static amount of time.
        """
        print("[+] Spidering target url ...")
        spider_target(target_url)

        waiting = 0
        while waiting != 100:
            if waiting % 5 == 0:
                print("Still Spidering")
            time.sleep(1)
            waiting += 1

        print("[+] Spidering complete ...")

        # check if site map content exists
        print("[+] Checking spidered URLs ...")
        content = site_map(target_url)
        if not content:
            print("No URL's have been discovered, scan cannot proceed.")
            sys.exit(1)
        else:
            print("URL's discovered:")
            for url in content['messages']:
                print(url['url'])

        print("[+] Performing active scan ...")
        active_scan(target_url)

        # get scan status
        while scan_status() != 100:
            time.sleep(20)
        print("\n[+] Scan completed")

        # generate scan report
        scan_report(target_url)

        # stop API service - commented out as this functionality is not working
        #burp_stop()

# Add target_url to scop
def add_scope(target_url):
    try:
        r = requests.put(
            "{}:{}/burp/target/scope?url={}".format(
                proxy_url,
                api_port,
                target_url
            )
        )
        r.raise_for_status()
        print("[+] {} included in scope".format(target_url))
    except requests.exceptions.RequestException as e:
        print("Error adding the target scope: {}".format(e))
        sys.exit(1)

# spider the target_url
def spider_target(target_url):
    try:
        r = requests.post(
            "{}:{}/burp/spider?baseUrl={}".format(
                proxy_url,
                api_port,
                target_url
            )
        )
        r.raise_for_status()
        print("[+] {} spidering commenced".format(target_url))
    except requests.exceptions.RequestException as e:
        print("Error spidering target scope: {}".format(e))
        sys.exit(1)

# Retrieve site map content
def site_map(target_url):
    print("[+] Retrieving the Burp site map ...")
    try:
        r = requests.get(
            "{}:{}/burp/target/sitemap?urlPrefix={}".format(
                proxy_url,
                api_port,
                target_url
                )
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error retrieving Burp site map items: {}".format(e))
        sys.exit(1)
    else:
        resp = r.json()
        print("SITE MAP:\n {}".format(resp))
        if resp['messages']:
            return resp
            """
            # Unique list of site map items
            host_set = {"{protocol}://{host}".format(**i)
                        for i in resp['messages']}
            print("[-] Found {} unique items in the Burp site map".format(
                len(host_set)
            ))
            return list(host_set)
            """
        else:
            print("[-] Burp site map is empty")

# Perform active scan
def active_scan(target_url):
    """Send a URL to Burp to perform active scan"""
    try:
        r = requests.post(
            "{}:{}/burp/scanner/scans/active?baseUrl={}".format(
                proxy_url,
                api_port,
                target_url
            )
        )
        r.raise_for_status()
        print("[-] {} Added to the scan queue".format(target_url))
    except requests.exceptions.RequestException as e:
        print("Error adding {} to the scan queue: {}".format(target_url, e))
        sys.exit(1)

# Check scan status
def scan_status():
    """Get the percentage completed for the scan queue items"""
    try:
        r = requests.get(
            "{}:{}/burp/scanner/status".format(
                proxy_url,
                api_port
            )
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error getting the scan status: {}".format(e))
    else:
        resp = r.json()
        sys.stdout.write("\r[-] Scan in progress: %{}".format(
            resp['scanPercentage'])
        )
        sys.stdout.flush()
        return resp['scanPercentage']

# Generate scan results report in XML
def scan_report(target_url):
    """
    Downloads the scan report with current Scanner issues for
    URLs matching the specified urlPrefix (HTML/XML)
    """
    try:
        r = requests.get(
            "{}:{}/burp/report?urlPrefix={}&reportType=XML".format(
                proxy_url,
                api_port,
                target_url,
            )
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Error downloading the scan report: {}".format(e))
    else:
        print("[+] Downloading XML report for {}".format(target_url))

        file_path = "/opt/stackstorm/scan_results/burp/burp_scan.xml"

        # Write the response body (byte array) to file
        with open(file_path, "wb+") as f:
            data = r.text
            # remove 0x85 byte from raw response
            data = re.sub(r'85', '', data)
            data = re.sub(r'c1', '', data)
            f.write(data)

        print("[+] Scan report saved to {}".format(file_path))

def burp_stop():
    try:
        r = requests.get(
            "{}:{}/burp/stop".format(proxy_url, api_port)
        )
	r.raise_for_status()
        print("[-] Burp is stopped")
    except requests.exceptions.RequestException as e:
        print("Error stopping the burp: {}".format(e))

 
