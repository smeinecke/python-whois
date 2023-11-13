import sys
from whois import NICClient
import re
import requests


WHOIS_SERVER_RE = re.compile(r"whois:(.*)\n", re.I)
COMMENTS_RE = re.compile(r"#.*")

# Manual override for some TLDs as whois in IANA is not correct
MANUAL_OVERRIDE = {
    "ru": "whois.nic.ru",
    "su": "whois.nic.ru",
    "xn--p1ai": "whois.nic.ru",
    "bz": "whois2.afilias-grs.net"
}


def crawl_iana_whois():
    nc = NICClient()
    res = requests.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
    tlds_str = COMMENTS_RE.sub('', res.text)
    for tld in tlds_str.split():
        tld = tld.strip().lower()

        w = nc.whois(tld, "whois.iana.org", 0 | NICClient.WHOIS_QUICK)
        f = WHOIS_SERVER_RE.search(w)
        if not f:
            raise Exception("No whois server found for %s" % tld)

        tld_whois = f.group(1).strip()

        with open('tld_whois_map.txt', 'a') as o:
            o.write("%s\t%s\n" % (tld, tld_whois))
            print("%s\t%s" % (tld, tld_whois))


def get_whois_map():
    whois_servers = {}
    with open('tld_whois_map.txt', 'r') as f:
        for line in f.readlines():
            tld, whois_server = line.split('\t')
            whois_server = whois_server.strip()
            if not whois_server or tld in MANUAL_OVERRIDE:
                continue

            # filter generic whois servers
            if 'whois.nic.' + tld == whois_server:
                continue

            if whois_server not in whois_servers:
                whois_servers[whois_server] = []

            whois_servers[whois_server].append(tld)

        for tld, whois_server in MANUAL_OVERRIDE.items():
            # filter generic whois servers
            if 'whois.nic.' + tld == whois_server:
                continue

            if whois_server not in whois_servers:
                whois_servers[whois_server] = []

            whois_servers[whois_server].append(tld)

    print(whois_servers)


if __name__ == "__main__":
    if '--crawl' in sys.argv:
        crawl_iana_whois()
    else:
        get_whois_map()
