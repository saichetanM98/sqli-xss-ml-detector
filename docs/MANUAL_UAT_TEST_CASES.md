# Manual UAT Test Cases: AI-Based Adaptive Security Gateway

This document provides a set of rigorous, real-world test cases designed to manually validate the security gateway using Postman or `curl`. Each test targets a specific subsystem (ML detection, Device Profiling, Threat Intel, or Behavior Analysis).

---

## Test Set 1: Pure Payload Detection (ML Engine)

### Test 1.1: Evasive SQL Injection
*Validates the ML model's ability to decode and classify obfuscated attacks without relying on simple regex.*
- **Method**: `POST`
- **URL**: `http://127.0.0.1:5000/predict`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
      "payload": "1'/*!50000UnION*/ /*!50000SeLeCt*/ 1,2,3-- -",
      "ip": "203.0.113.10"
  }
  ```
- **Expected Result**: `HTTP 403 Forbidden`
- **Validation Check**: `verdict` should be `BLOCK`, and `label` should be `sqli` with high confidence. The `policy_override` block should show a Zero-Tolerance override due to high confidence.

### Test 1.2: Evasive Cross-Site Scripting (XSS)
*Validates the ML model's ability to detect non-standard XSS vectors.*
- **Method**: `POST`
- **URL**: `http://127.0.0.1:5000/predict`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
      "payload": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
      "ip": "203.0.113.11"
  }
  ```
- **Expected Result**: `HTTP 403 Forbidden`
- **Validation Check**: `label` should be `xss` and `verdict` should be `BLOCK`.

---

## Test Set 2: Device Profiling & Threat Intel

### Test 2.1: Known Scanner (Nmap) sending Benign Traffic
*Validates that using a known malicious tool elevates the risk score, even if the payload is safe.*
- **Method**: `POST`
- **URL**: `http://127.0.0.1:5000/predict`
- **Headers**: 
  - `Content-Type: application/json`
  - `User-Agent`: `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`
- **Body**:
  ```json
  {
      "payload": "hello world",
      "ip": "203.0.113.12"
  }
  ```
- **Expected Result**: `HTTP 200 OK` (or `403` depending on strictness of scanner policy)
- **Validation Check**: Look in `data.device_profile`. `is_scanner` should be `true` and `scanner_name` should be `nmap`. The `behavior_score` should be highly elevated.

### Test 2.2: Bogon / Private IP Attack
*Validates the Threat Intel engine.*
- **Method**: `POST`
- **URL**: `http://127.0.0.1:5000/predict`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
      "payload": "safe payload",
      "ip": "127.0.0.1"
  }
  ```
- **Expected Result**: `HTTP 200 OK`
- **Validation Check**: Look at `data.threat_intel`. The `category` should be `private` or `bogon`, showing that the IP was successfully classified by the offline Threat Intel engine.

---

## Test Set 3: Behavioral Anomaly Engine (Rate Limiting)

### Test 3.1: Velocity Surge (Brute Force Simulation)
*Validates the sliding-window session manager.*
- **Method**: `POST`
- **URL**: `http://127.0.0.1:5000/predict`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
      "payload": "login attempt",
      "ip": "203.0.113.15"
  }
  ```
- **Action**: In Postman, click "Send" rapidly 25 times in under 10 seconds.
- **Expected Result**: The first ~20 requests will return `HTTP 200 OK`. The 21st request will return `HTTP 429 Too Many Requests`.
- **Validation Check**: `verdict` should be `RATE_LIMIT` and `data.session.is_rate_exceeded` should be `true`.

---

## Test Set 4: SOC Dashboard & Analyst Override

### Test 4.1: Human-in-the-Loop Blacklist
*Validates the Policy Engine's ability to prioritize Analyst decisions over all other math.*
- **Step 1 (Setup)**: Send a benign request from a specific IP:
  ```json
  {
      "payload": "innocent request",
      "ip": "203.0.113.99"
  }
  ```
  *(Result should be ALLOW)*
- **Step 2 (Action)**: Open the SOC Dashboard (`http://localhost:5173`). Find the incident, open the modal, and click **Blacklist IP**.
- **Step 3 (Verify)**: Resend the exact same benign request from Step 1.
- **Expected Result**: `HTTP 403 Forbidden`
- **Validation Check**: The payload is safe, but the request is blocked. Check `data.policy_override`. `override_applied` should be `true`, and `override_reason` should indicate an Analyst Blacklist.

---

**Proof of Execution:**  
When testing, save the raw JSON responses from Postman into a local text file or attach screenshots of the SOC Dashboard as cryptographic/immutable proof of validation for your audit trails.
