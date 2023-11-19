import socket
import sys
from whois import NICClient
import re
import requests
import dns.resolver


WHOIS_SERVER_RE = re.compile(r"whois:(.*)\n", re.I)
COMMENTS_RE = re.compile(r"#.*")

# Manual override for some TLDs as whois in IANA is not correct
MANUAL_OVERRIDE = {
    "net.ru": "whois.nic.ru",
    "org.ru": "whois.nic.ru",
    "pp.ru": "whois.nic.ru",
    "bm": "whois2.afilias-grs.net",  # internal whois server
    "bz": "whois2.afilias-grs.net",  # internal whois server
    "lc": "whois2.afilias-grs.net",  # internal whois server
    # centralnic 3rd level domains
    "ae.org": "whois.centralnic.com",
    "br.com": "whois.centralnic.com",
    "cn.com": "whois.centralnic.com",
    "co.com": "whois.centralnic.com",
    "co.nl": "whois.centralnic.com",
    "co.no": "whois.centralnic.com",
    "com.de": "whois.centralnic.com",
    "com.se": "whois.centralnic.com",
    "de.com": "whois.centralnic.com",
    "eu.com": "whois.centralnic.com",
    "gb.net": "whois.centralnic.com",
    "gr.com": "whois.centralnic.com",
    "hu.net": "whois.centralnic.com",
    "in.net": "whois.centralnic.com",
    "jp.net": "whois.centralnic.com",
    "jpn.com": "whois.centralnic.com",
    "mex.com": "whois.centralnic.com",
    "ru.com": "whois.centralnic.com",
    "sa.com": "whois.centralnic.com",
    "se.net": "whois.centralnic.com",
    "uk.com": "whois.centralnic.com",
    "uk.net": "whois.centralnic.com",
    "us.com": "whois.centralnic.com",
    "us.org": "whois.centralnic.com",
    "za.com": "whois.centralnic.com",
    "za.bz": "whois.centralnic.com",
    "ps": "registry.ps",  # internal whois server
    "bh": "whois.centralnic.com",  # internal whois server
    "ga": "whois.nic.ga",  # not listed in IANA
}


def get_iana_tld_list():
    res = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
    tlds_str = COMMENTS_RE.sub("", res.text)
    for tld in tlds_str.split():
        tld = tld.strip().lower()
        yield tld


backend_dns_servers = {
    "admin.tldns.godaddy.": "godaddy",
    "info.verisign-grs.com.": "verisign",
    "nstld.verisign-grs.com.": "verisign-cctld",
    "support.ryce-rsp.com.": "ryce-rsp",
    "regops.uniregistry.link.": "uniregistry",
    "ops.uniregistry.net.": "uniregistry",
    "dnsmaster.corenic.org.": "corenic",
    "admin-dns.cira.ca.": "cira",
    "hostmaster.donuts.email.": "IdentityDigitalInc",
    "hostmaster.nominet.org.uk.": "nominet",
    "hostmaster.nic.uk.": "nominet",
    "gtldsupport.aeda.ae.": "aeDA",
    "hostmaster.lemarit.com.": "lemarit",
    "cloud-dns-hostmaster.google.com.": "google",
    "tech.dk-hostmaster.dk.": "dk-hostmaster",
    "hostmaster.centralnic.net.": "centralnic",
    "noc.gmoregistry.net.": "gmo",
    "dnsmaster.irondns.net.": "irondns",
    "dnsmaster.afnic.fr.": "afnic",
    "hostmaster.coccaregistry.org.": "cocca",
    "root.conac.cn.": "conac",
    "ops.teleinfo.cn.": "teleinfo",
    "dns.registry.in.": "in-registry",
    ".cnnic.cn.": "cnnic",
    "hostmaster.tld-box.at.": "tld-box",
    "dna.sgnic.sg.": "sgnic",
    "td_dns_gtld.knet.cn.": "knet",
    "hostmaster.registro.br.": "registro.br",
    "support.registry.net.za.": "registry.net.za",
    ".eurid.eu.": "eurid",
    ".switch.ch.": "switch",
    ".hkirc.net.hk.": "hkirc",

}


def crawl_dns_soa():
    missing_whois = []
    with open("tld_whois_map.txt", "r") as f:
        for line in f.readlines():
            tld, whois_server = line.split("\t")
            whois_server = whois_server.strip()
            if tld in MANUAL_OVERRIDE:
                continue
            if not whois_server:
                missing_whois.append(tld)

    resolver = dns.resolver.Resolver()
    group_tlds = {}
    for tld in get_iana_tld_list():
        found_backend = None
        try:
            soa = resolver.resolve(tld, "SOA")
            soa_txt = soa[0].to_text()
            for x, backend in backend_dns_servers.items():
                if x in soa_txt:
                    found_backend = backend
                    if tld in missing_whois and len(tld) < 3:
                        print((tld, backend, soa_txt))
                    break
        except:
            pass

        if found_backend:
            if found_backend not in group_tlds:
                group_tlds[found_backend] = []
            group_tlds[found_backend].append(tld)
            continue
        # print(tld, soa_txt, found_backend)
    print(group_tlds['afnic'])


def check_whois_server(whois_server: str) -> bool:
    print("checking %s" % whois_server)
    try:
        socket.gethostbyname(whois_server)
    except socket.gaierror:
        return False

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((whois_server, 443))
    if result != 0:
        return False

    return True


def crawl_iana_whois():
    nc = NICClient()
    for tld in get_iana_tld_list():

        w = nc.whois(tld, "whois.iana.org", 0 | NICClient.WHOIS_QUICK)
        f = WHOIS_SERVER_RE.search(w)
        if not f:
            raise Exception("No whois server found for %s" % tld)

        tld_whois = f.group(1).strip()

        with open("tld_whois_map.txt", "a") as o:
            o.write("%s\t%s\n" % (tld, tld_whois))
            print("%s\t%s" % (tld, tld_whois))


def get_whois_map(check_whois: bool = False):
    whois_servers = {}
    no_whois_server = []
    with open("tld_whois_map.txt", "r") as f:
        for line in f.readlines():
            tld, whois_server = line.split("\t")
            whois_server = whois_server.strip()
            if tld in MANUAL_OVERRIDE:
                continue

            if not whois_server and len(tld) < 3:  # only disable for ccTLDs - gTLDs should have a whois server
                if tld in NICClient.NO_WHOIS_SERVER:
                    no_whois_server.append(tld)
                    continue

                whois_server = "whois.nic." + tld
                if not check_whois or not check_whois_server(whois_server):
                    no_whois_server.append(tld)
                else:
                    whois_servers[whois_server] = [tld]
                continue

            # filter generic whois servers
            if "whois.nic." + tld == whois_server:
                continue

            if whois_server not in whois_servers:
                whois_servers[whois_server] = []

            whois_servers[whois_server].append(tld)

        for tld, whois_server in MANUAL_OVERRIDE.items():
            # filter generic whois servers
            if "whois.nic." + tld == whois_server:
                continue

            if whois_server not in whois_servers:
                whois_servers[whois_server] = []

            whois_servers[whois_server].append(tld)

    print(whois_servers)
    print(repr(no_whois_server))


if __name__ == "__main__":
    if "--crawl" in sys.argv:
        crawl_iana_whois()
    elif "--soa" in sys.argv:
        crawl_dns_soa()
    else:
        check_whois = False
        if '--check' in sys.argv:
            check_whois = True
        get_whois_map(check_whois)
