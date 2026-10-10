import requests
import json
import time
import argparse
from typing import List, Dict

API_URL = "http://127.0.0.1:5000/predict"

EVASIVE_PAYLOADS = [
    # Evasive SQLi
    "1'/*!50000UnION*/ /*!50000SeLeCt*/ 1,2,3-- -",
    "admin' OR 1=1--",
    "1'; EXEC xp_cmdshell('dir');--",
    "admin' /*!OR*/ '1'='1",
    "%27%20OR%201%3D1--",
    # Evasive XSS
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    "<scr\0ipt>alert(1)</script>",
    # Mixed / Generic
    "../../../etc/passwd",
]

def simulate_attacks():
    print(f"Starting attack simulation on {API_URL}...")
    success_count = 0
    total = len(EVASIVE_PAYLOADS)

    for i, payload in enumerate(EVASIVE_PAYLOADS, 1):
        print(f"\n[{i}/{total}] Testing payload: {payload}")
        data = {
            "payload": payload,
            "ip": f"192.168.1.{i}", # rotate IP to avoid rate limit
            "headers": {
                "User-Agent": "python-requests/attack-sim"
            }
        }
        try:
            resp = requests.post(API_URL, json=data)
            # The API returns 403 for BLOCK
            if resp.status_code == 403:
                result = resp.json()
                print(f"✅ BLOCKED correctly. Confidence: {result.get('confidence', 0):.2f}, Verdict: {result.get('verdict')}")
                success_count += 1
            else:
                result = resp.json()
                print(f"❌ FAILED TO BLOCK. Status: {resp.status_code}, Verdict: {result.get('verdict')}")
        except Exception as e:
            print(f"Error testing payload: {e}")
        
        time.sleep(0.1)

    print(f"\n--- Simulation Complete ---")
    print(f"Successfully blocked {success_count}/{total} evasive payloads ({(success_count/total)*100:.1f}%)")

if __name__ == "__main__":
    simulate_attacks()
