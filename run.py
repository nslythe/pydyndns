import CloudFlare
import requests
import json
import os
import datetime
import logging
import signal
import threading

ip_urls = {
    "https://ifconfig.net" : "json",
    "https://ifconfig.co": "json",
    "https://ipinfo.io/ip" : "str"
}

API_KEY = os.getenv("CLOUDFLARE_API_KEY")
ZONE_NAME = os.getenv("ZONE_NAME")
HOST_NAME = os.getenv("HOST_NAME")
TTL = int(os.getenv("TTL", 0)) * 60


LOOP_TIME = 15

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

event = threading.Event()
def handler(signum, frame):
    logging.info(f"Received signal STOPPING")
    event.set()


def main():
    signal.signal(signal.SIGINT, handler)
    if API_KEY is None or ZONE_NAME is None or HOST_NAME is None:
        logging.error("You need to define env variable API_KEY, ZONE_NAME and HOST_NAME")
        return
    while True:
        do_update(hostname = HOST_NAME, zone_name = ZONE_NAME, ttl = TTL)
        if event.wait(LOOP_TIME):
            break


def do_update(hostname, zone_name, ttl, force = False):
    try:
        current_ip = get_current_ip()
        logging.info("Discovered current IP : %s", current_ip)
        if current_ip is not None:
            renew_ip = get_renew_ip(current_ip, force = force)
            if renew_ip is not None:
                logging.info("Will renew with : %s (force:%s)", current_ip, force)
                update_cloudflare(renew_ip, hostname = hostname, zone_name = zone_name, ttl = ttl, create_if_record_doesnot_exists = True, force = force)
                logging.info("Updated : %s.%s -> %s", hostname, zone_name, renew_ip)
            else:
                logging.info("No update same has cache")
        else:
            logging.error("Unable to get public ip")
    except Exception as e:
        logging.error(e)


def update_cloudflare(renew_ip, *, hostname, zone_name, ttl = None, create_if_record_doesnot_exists = False, force = False):
    cf = CloudFlare.CloudFlare(key=API_KEY)
    zones = cf.zones.get(params={'name': zone_name})
    if len(zones) != 1:
        raise Exception(f"Zone {zone_name} not found")
    zone = zones[0]

    dns_records = cf.zones.dns_records.get(zone["id"], params={'name':hostname + '.' + zone_name})
    if len(dns_records) != 1:
        if create_if_record_doesnot_exists:         
            data = {'name':hostname,
                 'type':'A',
                 'content': renew_ip}
            if ttl > 60:
                data["ttl"] = ttl
            r = cf.zones.dns_records.post(zone["id"], data=data)
        else:
            raise Exception(f"Zones {hostname} record not found in zone {zone_name}")
    else:
        dns_record = dns_records[0]
        if dns_record["content"] == renew_ip and not force:
            raise Exception(f"Record : {hostname}.{zone_name} already have ip : {renew_ip}")
        
        dns_record["content"] = renew_ip
        if ttl > 60:
            dns_record["ttl"] = ttl
        dns_record = cf.zones.dns_records.put(zone["id"], dns_record["id"], data = dns_record)


def get_current_ip():
    ip = None
    found = False
    
    for url in ip_urls.keys():
        found_ip = None
        t = ip_urls[url]
        if t == "json":
            response = requests.get(url, headers={"Accept": "application/json"})
            obj = response.json()
            found_ip = obj["ip"].strip()
        elif t == "str":
            response = requests.get(url)
            found_ip = response.content.strip()

        if found_ip is not None:
            if ip is None:
                ip = found_ip
            else:
                if found_ip == ip:
                    found = True
                    break

    if not found:
        raise Exception("Unable to get public IP")
    
    return ip


def get_renew_ip(current_ip, force = False):
    ip_cached_fle_path = "ip_cached"
    renew_ip = None
    cached_ip = None
    if os.path.exists(ip_cached_fle_path):
        try:
            with open(ip_cached_fle_path, "r") as f:
                obj = json.load(f)
                cached_ip = obj["ip"]
        except Exception as e:
            pass

    if (cached_ip != current_ip) or force:
        with open(ip_cached_fle_path, "w") as f:
            json.dump({
                "ip": current_ip,
                "date" : datetime.datetime.now().timestamp()
                }, f)
        renew_ip = current_ip

    return renew_ip


if __name__ == '__main__':
    main()
