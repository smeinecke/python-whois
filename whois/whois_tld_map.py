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
    "bz": "whois2.afilias-grs.net"
}


def get_iana_tld_list():
    res = requests.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
    tlds_str = COMMENTS_RE.sub('', res.text)
    for tld in tlds_str.split():
        tld = tld.strip().lower()
        yield tld


backend_dns_servers = {
    'admin.tldns.godaddy.': 'godaddy',
    'info.verisign-grs.com.': 'verisign',
    'nstld.verisign-grs.com.': 'verisign-cctld',
    'support.ryce-rsp.com.': 'ryce-rsp',
    'regops.uniregistry.link.': 'uniregistry',
    'ops.uniregistry.net.': 'uniregistry',
    'dnsmaster.corenic.org.': 'corenic',
    'admin-dns.cira.ca.': 'cira',
    'hostmaster.donuts.email.': 'IdentityDigitalInc',
    'hostmaster.nominet.org.uk.': 'nominet',
    'hostmaster.nic.uk.': 'nominet',
    'gtldsupport.aeda.ae.': 'aeDA',
    'hostmaster.lemarit.com.': 'lemarit',
    'cloud-dns-hostmaster.google.com.': 'google',
    'tech.dk-hostmaster.dk.': 'dk-hostmaster',
    'hostmaster.centralnic.net.': 'centralnic',
    'noc.gmoregistry.net.': 'gmo',
    'dnsmaster.irondns.net.': 'irondns',
    'dnsmaster.afnic.fr.': 'afnic',
    'hostmaster.coccaregistry.org.': 'cocca',
    'root.conac.cn.': 'conac',
    'ops.teleinfo.cn.': 'teleinfo',
    'dns.registry.in.': 'in-registry',
    '.cnnic.cn.': 'cnnic',
    'hostmaster.tld-box.at.': 'tld-box',
    'dna.sgnic.sg.': 'sgnic',
    'td_dns_gtld.knet.cn.': 'knet',
    'hostmaster.registro.br.': 'registro.br',
    'support.registry.net.za.': 'registry.net.za',
    '.eurid.eu.': 'eurid',
    '.switch.ch.': 'switch',
    '.hkirc.net.hk.': 'hkirc',

}


def crawl_dns_soa():
    resolver = dns.resolver.Resolver()
    group_tlds = {}
    for tld in get_iana_tld_list():
        found_backend = None
        try:
            soa = resolver.resolve(tld, 'SOA')
            soa_txt = soa[0].to_text()
            for x, backend in backend_dns_servers.items():
                if x in soa_txt:
                    found_backend = backend
                    break
        except:
            pass
        if found_backend:
            if found_backend not in group_tlds:
                group_tlds[found_backend] = []
            group_tlds[found_backend].append(tld)
            continue
        # print(tld, soa_txt, found_backend)
    print(group_tlds)


def crawl_iana_whois():
    nc = NICClient()
    for tld in get_iana_tld_list():

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
    elif '--soa' in sys.argv:
        crawl_dns_soa()
    else:
        get_whois_map()
