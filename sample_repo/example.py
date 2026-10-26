"""Small sample file for a quick local test. This file is deliberately illustrative."""

import subprocess
import requests

API_TOKEN = "example_token_value_123456"
def run_command(user_value):
    # Illustrative risky pattern: never use untrusted input in a shell command.
    return subprocess.run("echo " + user_value, shell=True)

def fetch_data(url):
    return requests.get(url)

def parse_value(text):
    return eval(text)

def old_handler():
    try:
        risky_operation()
    except:
        print("debug: failed")
