#!/usr/bin/env python

import argparse
import os
import sys
import tempfile
import time
import re

import requests

target_url = None           # user-specified target
api_port = "8090"           # default api port
proxy_url = "http://127.0.0.1"     # default proxy url
proxy_port = "8080"         # default proxy port

"""
Add target_url to scope
"""
def add_scope():
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

"""
Spider the target_url
"""
def spider_target():
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

"""
Retrieve site map content
"""
def site_map():
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
    # continue if no exception
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

"""
Perform active scan
"""
def active_scan():
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

"""
Check scan status
"""
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

"""
Download scan report for the target URL in XML format
"""
def scan_report():
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
        # Write the response body (byte array) to file
        file_name = "burp-report_{}_{}.xml".format(
            time.strftime("%Y%m%d-%H%M%S", time.localtime()),
            target_url.replace("://", "-"),
        )
        file = os.path.join(tempfile.gettempdir(), file_name)
        # remove 0x85 byte from raw response
        data = r.text
        data = re.sub(r'85', '', data)
        data = re.sub(r'c1', '', data)

        # write results to file
        with open(file, 'wb') as f:
            f.write(data)
        print("[+] Scan report saved to {}".format(file))
        return file_name

def main():
    # adding target to scope
    print("[+] Adding target url to scope ...")
    add_scope()

    """
    Need better way to know when spider queue = 0.
    Currently, just waiting a static amount of time.
    """
    print("[+] Spidering target url ...")
    spider_target()
    
    waiting = 0
    while waiting != 100:
        if waiting % 5 == 0:
            print("Still Spidering")
        time.sleep(1)
        waiting += 1

    print("[+] Spidering complete ...")

    # check if site map content exists
    print("[+] Checking spidered URLs ...")
    content = site_map()
    if not content:
        print("No URL's have been discovered, scan cannot proceed.")
        sys.exit(1)
    else:
        print("URL's discovered:")
        for url in content['messages']:
            print(url['url'])

    print("[+] Performing active scan ...")
    active_scan()

    # get scan status
    while scan_status() != 100:
        time.sleep(20)
    print("\n[+] Scan completed")

    # get scan report
    report = scan_report()

if __name__ == '__main__':
    # check usage
    if len(sys.argv) != 2:
        print("ERROR: Too few arguments.\n")
        print("usage:   python burpauto.py [target_url]")
        print("example: python burpauto.py http://example.com")
    # set target URL and run main program
    else:
        target_url = sys.argv[1]
        main()
