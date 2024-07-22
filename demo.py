#!/usr/bin/env python3
"""Command-line interface to perform several security tests."""

import json
import subprocess
import warnings

from lxml import html
import nmap3
import requests
import whois
import typer
from Wappalyzer import Wappalyzer, WebPage

app = typer.Typer()

# Workaround for https://github.com/chorsley/python-Wappalyzer/issues/40
warnings.simplefilter("ignore")


def get_page(url: str, proxy: str = None):
    """Perform a GET request and return response object."""
    proxies = None
    if proxy:
        proxies = {"http": f"http://{proxy}"}
    response = requests.get(url, proxies=proxies)
    return response


def post_page(url: str, proxy: str = None, data: dict = None):
    """Perform a POST request and return response object."""
    proxies = None
    if proxy:
        proxies = {"http": f"http://{proxy}"}
    response = requests.post(url, proxies=proxies, data=data, allow_redirects=False)
    return response


@app.command()
def analyze(url: str, proxy: str = None):
    """Analyze page and display framework and versions."""
    response = get_page(url, proxy)
    webpage = WebPage.new_from_response(response)
    wappalyzer = Wappalyzer.latest()
    results = wappalyzer.analyze_with_versions_and_categories(webpage)
    print(json.dumps(results, indent=2))


@app.command()
def discover(url: str, wordlist: str = "/dev/null"):
    """Brute-force file and directory names."""
    subprocess.run(["gobuster", "-u", url, "-w", wordlist], check=True)


@app.command()
def forms(url: str, proxy: str = None):
    """Find a form in a page, and print form details."""
    response = get_page(url, proxy)
    tree = html.fromstring(response.content)
    for form in tree.xpath("//form"):
        print(f"Found a {form.method} form for {form.action}")
        for field in form.fields:
            print(f"Contains input field {field}")


@app.command()
def domain(name: str):
    """Print the domain registrant's name and organization."""
    results = whois.whois(name)
    print(f"{name} is registered by {results.name} - {results.org}")


@app.command()
def login(
    url: str,
    username: str,
    password: str,
    uservariable: str = "username",
    proxy: str = None,
):
    """Post a username and password."""
    data = {uservariable: username, "password": password}
    response = post_page(url, proxy=proxy, data=data)
    if response.status_code not in [200, 302]:
        return False
    if response.status_code == 302:
        if url in response.headers["Location"]:
            return False
        print(f"Redirected to {response.headers['Location']}")
    print(f"Seems like login succeeded with {username} and {password}")
    if response.content:
        print(response.content)
    if response.cookies:
        print(f"Received cookies: {response.cookies}")
    return True


@app.command()
def brute(url: str, username: str, wordlist: str, proxy: str = None):
    """Brute-force password logins using a wordlist."""
    with open(wordlist, encoding="utf-8") as handle:
        passwords = handle.read().splitlines()
    for password in passwords:
        if login(url, username, password, proxy=proxy):
            break


@app.command()
def portscan(target: str, top: int = 10):
    """Perform a portscan against a target on the top TOP ports,
    and print the open ports and services."""
    nmap = nmap3.Nmap()
    results = nmap.scan_top_ports(target, default=top)
    ip, *_unused = results.keys()
    for port in results[ip]["ports"]:
        if "open" in port["state"]:
            print(f"{port['portid']} {port['service']['name']}")


if __name__ == "__main__":
    app()
