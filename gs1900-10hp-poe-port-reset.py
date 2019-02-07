#!/usr/bin/python3
# https://spdx.org/licenses/ISC.html
#
# Copyright (c) 2019 Sebastian Reichel <sre@mainframe.io>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

from urllib.parse import urlencode, quote_plus
import http.client
import time, math, random, sys, re
import requests

ssidre = re.compile('setCookie\("XSSID", "(\w{32})"\)')

# password obfuscation from zyxel
def zyxel_encode_pw(plaintext):
    result = "";
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    i = len(plaintext)-1

    for x in range(0, 320):
        if x % 7 == 6 and i >= 0:
            result += plaintext[i]
            i-=1
        elif x == 122:
            if len(plaintext) < 10:
                result += "0"
            else:
                result += str(math.floor(len(plaintext)/10))[0]
        elif x == 288:
            result += str(len(plaintext)%10)
        else:
            result += alphabet[random.randint(0, len(alphabet)-1)]

    return result

# username, password -> SSID
def zyxel_login(address, username, password):
    con = http.client.HTTPConnection(address)
    params={'login': 1, 'username': username, 'password': zyxel_encode_pw(password), 'dummy': int(time.time() * 1000)}
    con.request("GET", "/cgi-bin/dispatcher.cgi?" + urlencode(params, quote_via=quote_plus))
    login = con.getresponse()

    time.sleep(0.5)

    newparams={'login_chk': 1, 'dummy': int(time.time() * 1000)}
    con.request("GET", "/cgi-bin/dispatcher.cgi?" + urlencode(newparams, quote_via=quote_plus))
    chk = con.getresponse()

    data = chk.read()
    if b"OK" not in data:
        return None

    con.request("GET", "/cgi-bin/dispatcher.cgi?cmd=1")
    cmd1 = con.getresponse()
    cmd1data = cmd1.read().decode("utf-8")
    ssidmatch = ssidre.search(cmd1data)
    ssid = ssidmatch.group(1)

    return ssid

# set PoE state, resets other settings
def zyxel_poe_port_set(address, ssid, port, state):
    payload = {'XSSID': ssid, "cmd": 775, "portlist": port, "state": state, "portPriority": 3, "portPowerMode": 0, "portRangeDetection": 0, "portLimitMode": 0, "poeTimeRange": 20, "sysSubmit": "Apply"}
    cookies = {"XSSID": ssid}

    r = requests.post('http://'+address + '/cgi-bin/dispatcher.cgi', data=payload, cookies=cookies)

    if "cmd=773" in r.text:
        return True
    return False

# reset PoE state
def zyxel_poe_port_reset(address, ssid, port):
    if not zyxel_poe_port_set(address, ssid, port, 0):
        return False
    time.sleep(3)
    return zyxel_poe_port_set(address, ssid, port, 1)

##############################################################

if len(sys.argv) < 5:
    print(sys.argv[0] + " <IP> <username> <password> <port>")
    print("tool to reset PoE state for a GS1900-10HP port")
    sys.exit(1)

address = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
port = sys.argv[4]

ssid = zyxel_login(address, username, password)
if ssid == None:
    print("Login failed!")
    sys.exit(1)

if not zyxel_poe_port_reset(address, ssid, port):
    print("PoE Port reset failed!")
    sys.exit(0)
