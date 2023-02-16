import CloudFlare
import requests
import json
import os

ip_urls = {
    "https://ifconfig.net" : "json",
    "https://ifconfig.co": "json",
    "https://ipinfo.io/ip" : "str"
}

API_KEY = os.getenv("API_KEY")

def main():
    current_ip = get_current_ip()
    if current_ip is not None:
        renew_ip = get_renew_ip(current_ip, force = True)
        if renew_ip is not None:
            update_cloudflare(renew_ip)
    else:
        print ("error getting public ip")

def update_cloudflare(renew_ip):
    cf = CloudFlare.CloudFlare(key=API_KEY)
    zone_name = "slythe.net"
    zones = cf.zones.get(params={'name': zone_name})
    if len(zones) != 1:
        raise Exception("Zones not found")
    zone = zones[0]

    dns_records = cf.zones.dns_records.get(zone["id"], params={'name':"h1a" + '.' + zone_name})
    if len(dns_records) != 1:
        raise Exception("Zones record not found")
    dns_record = dns_records[0]
    
    if dns_record["content"] == renew_ip:
        raise Exception("Same IP no update to do")

    dns_record["content"] = renew_ip
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
            json.dump({"ip": current_ip}, f)
        renew_ip = current_ip

    return renew_ip



if __name__ == '__main__':
    main()
