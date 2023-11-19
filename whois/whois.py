# -*- coding: utf-8 -*-

"""
Whois client for python

transliteration of:
http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

Copyright (c) 2010 Chris Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from future import standard_library

import os
import optparse
import socket
import sys
import re
from builtins import *
import logging
standard_library.install_aliases()

logger = logging.getLogger(__name__)


class NICClient(object):
    NO_WHOIS_SERVER = ['ad', 'ao', 'aq', 'az', 'bb', 'bd', 'bs', 'bt', 'bv', 'cg', 'ck', 'cm', 'cu', 'cv', 'cw', 'cy', 'dj', 'eg', 'er', 'et', 'fk',
                       'gb', 'gm', 'gr', 'gt', 'gu', 'gw', 'jm', 'jo', 'kh', 'km', 'kp', 'kw', 'lk', 'lr', 'mc', 'mh', 'mp', 'mt', 'mv', 'ne', 'ni',
                       'np', 'nr', 'pa', 'pg', 'ph', 'pn', 'py', 'sd', 'sj', 'sr', 'sv', 'sz', 'tj', 'tt', 'va', 'vi', 'zw']
    WHOIS_SERVERS = {
        "whois.nic.google": [
            "ads",
            "android",
            "app",
            "boo",
            "cal",
            "channel",
            "chrome",
            "dad",
            "day",
            "dclk",
            "dev",
            "docs",
            "drive",
            "eat",
            "esq",
            "fly",
            "foo",
            "gbiz",
            "gle",
            "gmail",
            "goog",
            "guge",
            "hangout",
            "here",
            "how",
            "ing",
            "map",
            "meet",
            "meme",
            "mov",
            "new",
            "nexus",
            "page",
            "phd",
            "play",
            "prod",
            "prof",
            "rsvp",
            "search",
            "soy",
            "xn--flw351e",
            "xn--q9jyb4c",
            "xn--qcka1pmc",
            "youtube",
            "zip",
        ],
        "whois.aeda.net.ae": ["ae", "xn--mgbaam7a8h"],
        "whois.aero": ["aero"],
        "whois.amnic.net": ["am", "xn--y9a3aq"],
        "whois.teleinfo.cn": [
            "anquan",
            "shouji",
            "xihuan",
            "xn--3ds443g",
            "xn--fiq228c5hs",
            "xn--vuq861b",
            "yun",
        ],
        "whois.iana.org": ["arpa", "int"],
        "whois.auda.org.au": ["au"],
        "whois.ax": ["ax"],
        "whois.gtld.knet.cn": [
            "baidu",
            "wang",
            "xn--30rr7y",
            "xn--3bst00m",
            "xn--45q11c",
            "xn--6qq986b3xl",
            "xn--9et52u",
            "xn--czru2d",
            "xn--fiq64b",
            "xn--hxt814e",
        ],
        "whois.dns.be": ["be"],
        "whois.registre.bf": ["bf"],
        "whois.register.bg": ["bg"],
        "whois1.nic.bi": ["bi"],
        "whois.bnnic.bn": ["bn"],
        "whois.gtlds.nic.br": ["bom", "final", "globo", "natura", "rio", "uol"],
        "whois.registro.br": ["br"],
        "whois.nic.net.bw": ["bw"],
        "whois.cctld.by": ["by", "xn--90ais"],
        "whois.cira.ca": ["ca"],
        "ccwhois.verisign-grs.com": ["cc"],
        "whois.dot.cf": ["cf"],
        "whois.cnnic.cn": ["cn"],
        "whois.ryce-rsp.com": ["cologne", "koeln"],
        "whois.verisign-grs.com": ["com", "net"],
        "whois.nic.gmo": [
            "datsun",
            "fujitsu",
            "goo",
            "hisamitsu",
            "hitachi",
            "infiniti",
            "jcb",
            "mitsubishi",
            "nissan",
            "panasonic",
            "sharp",
            "yodobashi",
        ],
        "whois.denic.de": ["de"],
        "whois.punktum.dk": ["dk"],
        "whois.dmdomains.dm": ["dm"],
        "whois.educause.edu": ["edu"],
        "whois.tld.ee": ["ee"],
        "whois.centralnic.com": [
            "etisalat",
            "xn--mgbaakc7dvf",
            "ae.org",
            "br.com",
            "cn.com",
            "co.com",
            "co.nl",
            "co.no",
            "com.de",
            "com.se",
            "de.com",
            "eu.com",
            "gb.net",
            "gr.com",
            "hu.net",
            "in.net",
            "jp.net",
            "jpn.com",
            "mex.com",
            "ru.com",
            "sa.com",
            "se.net",
            "uk.com",
            "uk.net",
            "us.com",
            "us.org",
            "za.com",
            "za.bz",
            "bh",
        ],
        "whois.eu": ["eu", "xn--e1a4c", "xn--qxa6a"],
        "whois.fi": ["fi"],
        "www.whois.fj": ["fj"],
        "whois.mediaserv.net": ["gf", "mq"],
        "whois.gg": ["gg"],
        "whois2.afilias-grs.net": ["gi", "sc", "vc", "bz", "lc", "bm"],
        "whois.uniregistry.net": ["gift", "juegos", "link", "tattoo"],
        "whois.ande.gov.gn": ["gn"],
        "whois.dotgov.gov": ["gov"],
        "whois.dominio.gq": ["gq"],
        "whois.registry.gy": ["gy"],
        "whois.hkirc.hk": ["hk", "xn--j6w193g"],
        "whois.registry.hm": ["hm"],
        "whois.dns.hr": ["hr"],
        "whois.id": ["id"],
        "whois.weare.ie": ["ie"],
        "whois.isoc.org.il": ["il", "xn--4dbrk0ce"],
        "whois.registry.in": [
            "in",
            "xn--2scrj9c",
            "xn--3hcrj9c",
            "xn--45br5cyl",
            "xn--45brj9c",
            "xn--fpcrj9c3d",
            "xn--gecrj9c",
            "xn--h2breg3eve",
            "xn--h2brj9c",
            "xn--h2brj9c8c",
            "xn--mgbbh1a",
            "xn--mgbbh1a71e",
            "xn--mgbgu82a",
            "xn--rvc1e0am3e",
            "xn--s9brj9c",
            "xn--xkc2dl3a5ee0h",
        ],
        "whois.cmc.iq": ["iq", "xn--mgbtx2b"],
        "whois.isnic.is": ["is"],
        "whois.je": ["je"],
        "whois.jprs.jp": ["jp"],
        "whois.kenic.or.ke": ["ke"],
        "whois.kg": ["kg"],
        "whois.kr": ["kr", "xn--3e0b707e", "xn--cg4bki"],
        "whois.kyregistry.ky": ["ky"],
        "whois.lbdr.org.lb": ["lb"],
        "whois.domreg.lt": ["lt"],
        "whois.dns.lu": ["lu"],
        "whois.registre.ma": ["ma"],
        "whois.marnet.mk": ["mk", "xn--d1alf"],
        "whois.registry.gov.mm": ["mm"],
        "whois.monic.mo": ["mo", "xn--mix891f"],
        "whois.mx": ["mx"],
        "whois.mynic.my": ["my", "xn--mgbx4cd0ab"],
        "whois.na-nic.com.na": ["na"],
        "whois.nc": ["nc"],
        "whois.nic.net.ng": ["ng"],
        "whois.domain-registry.nl": ["nl"],
        "whois.norid.no": ["no"],
        "whois.iis.nu": ["nu"],
        "whois.irs.net.nz": ["nz"],
        "whois.registry.om": ["om", "xn--mgb9awbf"],
        "whois.publicinterestregistry.org": ["org"],
        "kero.yachay.pe": ["pe"],
        "whois.registry.pf": ["pf"],
        "whois.pknic.net.pk": ["pk"],
        "whois.dns.pl": ["pl"],
        "whois.dotpostregistry.net": ["post"],
        "whois.afilias-srs.net": ["pr", "schaeffler", "shaw"],
        "whois.dns.pt": ["pt"],
        "whois.registry.qa": ["qa", "xn--wgbl6a"],
        "whois.rotld.ro": ["ro"],
        "whois.rnids.rs": ["rs", "xn--90a3ac"],
        "whois.tcinet.ru": ["ru", "su", "xn--p1ai"],
        "whois.ricta.org.rw": ["rw"],
        "whois.nic.net.sa": ["sa", "xn--mgberp4a5d4ar"],
        "whois.nic.net.sb": ["sb"],
        "whois.iis.se": ["se"],
        "whois.sgnic.sg": ["sg", "xn--clchc0ea0b2g2a9gcd", "xn--yfro4i67o"],
        "whois.register.si": ["si"],
        "whois.sk-nic.sk": ["sk"],
        "whois.sx": ["sx"],
        "whois.tld.sy": ["sy", "xn--ogbpf8fl"],
        "whois.thnic.co.th": ["th", "xn--o3cw4h"],
        "whois.dot.tk": ["tk"],
        "whois.ati.tn": ["tn", "xn--pgbs0dh"],
        "whois.tonic.to": ["to"],
        "whois.trabis.gov.tr": ["tr"],
        "whois.twnic.net.tw": ["tw", "xn--kprw13d", "xn--kpry57d"],
        "whois.tznic.or.tz": ["tz"],
        "whois.ua": ["ua"],
        "whois.co.ug": ["ug"],
        "whois.nic.org.uy": ["uy"],
        "whois.cctld.uz": ["uz"],
        "whois.dnrs.vu": ["vu"],
        "whois.website.ws": ["ws"],
        "whois.ngtld.cn": ["xn--1qqw23a", "xn--55qx5d", "xn--io0a7i", "xn--xhq521b"],
        "whois.conac.cn": ["xn--55qw42g", "xn--zfr164b"],
        "whois.nic.kz": ["xn--80ao21a"],
        "whois.imena.bg": ["xn--90ae"],
        "cwhois.cnnic.cn": ["xn--fiqs8s", "xn--fiqz9s"],
        "whois.dotukr.com": ["xn--j1amh"],
        "whois.nic.dz": ["xn--lgbbat1ad8j"],
        "whois.nic.ir": ["xn--mgba3a4f16a"],
        "whois.nic.mr": ["xn--mgbah1a3hjkrd"],
        "whois.itdc.ge": ["xn--node"],
        "whois.nic.la": ["xn--q7ce6a"],
        "whois.pnina.ps": ["xn--ygbi2ammx"],
        "whois.y.net.ye": ["ye"],
        "whois.zicta.zm": ["zm"],
        "whois.nic.ru": ["net.ru", "org.ru", "pp.ru"],
        "registry.ps": ["ps"],
    }

    ABUSEHOST = "whois.abuse.net"
    ANICHOST = "whois.arin.net"
    BNICHOST = "whois.registro.br"
    DEFAULT_PORT = "nicname"
    DNICHOST = "whois.nic.mil"
    GNICHOST = "whois.nic.gov"
    IANAHOST = "whois.iana.org"
    INICHOST = "whois.networksolutions.com"
    LNICHOST = "whois.lacnic.net"
    MNICHOST = "whois.ra.net"
    NICHOST = "whois.crsnic.net"
    NORIDHOST = "whois.norid.no"
    PANDIHOST = "whois.pandi.or.id"
    PNICHOST = "whois.apnic.net"
    QNICHOST_HEAD = "whois.nic."
    QNICHOST_TAIL = ".whois-servers.net"
    RNICHOST = "whois.ripe.net"
    SNICHOST = "whois.6bone.net"

    DE_HOST = "whois.denic.de"
    DK_HOST = "whois.dk-hostmaster.dk"
    PPUA_HOST = "whois.pp.ua"

    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois = [LNICHOST, RNICHOST, PNICHOST, BNICHOST, PANDIHOST]

    WHOIS_RECURSE_TLDS = ["com", "net"]

    def __init__(self):
        self.use_qnichost = False

    @staticmethod
    def findwhois_server(buf, hostname, query):
        """Search the initial TLD lookup results for the regional-specific
        whois server for getting contact details.
        """
        nhost = None
        match = re.compile(r'Domain Name: {}\s*.*?Whois Server: (.*?)\s'.format(query),
                           flags=re.IGNORECASE | re.DOTALL).search(buf)
        if match:
            nhost = match.groups()[0]
            # if the whois address is domain.tld/something then
            # s.connect((hostname, 43)) does not work
            if nhost.count('/') > 0:
                nhost = None
        elif hostname == NICClient.ANICHOST:
            for nichost in NICClient.ip_whois:
                if buf.find(nichost) != -1:
                    nhost = nichost
                    break
        return nhost

    def whois(self, query, hostname, flags, many_results=False, quiet=False):
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specific whois server and do a lookup
        there for contact details.  If `quiet` is `True`, will
        not send a message to logger when a socket error
        is encountered.
        """
        response = b''
        if "SOCKS" in os.environ:
            try:
                import socks
            except ImportError as e:
                logger.error("You need to install the Python socks module. Install PIP "
                             "(https://bootstrap.pypa.io/get-pip.py) and then 'pip install PySocks'")
                raise e
            socks_user, socks_password = None, None
            if "@" in os.environ["SOCKS"]:
                creds, proxy = os.environ["SOCKS"].split("@")
                socks_user, socks_password = creds.split(":")
            else:
                proxy = os.environ["SOCKS"]
            socksproxy, port = proxy.split(":")
            socks_proto = socket.AF_INET
            if socket.AF_INET6 in [sock[0] for sock in socket.getaddrinfo(socksproxy, port)]:
                socks_proto = socket.AF_INET6
            s = socks.socksocket(socks_proto)
            s.set_proxy(socks.SOCKS5, socksproxy, int(port), True, socks_user, socks_password)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        try:  # socket.connect in a try, in order to allow things like looping whois on different domains without
            # stopping on timeouts: https://stackoverflow.com/questions/25447803/python-socket-connection-exception
            s.connect((hostname, 43))
            try:
                query = query.decode('utf-8')
            except UnicodeEncodeError:
                pass  # Already Unicode (python2's error)
            except AttributeError:
                pass  # Already Unicode (python3's error)

            if hostname == NICClient.DE_HOST:
                query_bytes = "-T dn,ace -C UTF-8 " + query
            elif hostname == NICClient.DK_HOST:
                query_bytes = " --show-handles " + query
            elif hostname.endswith(NICClient.QNICHOST_TAIL) and many_results:
                query_bytes = '=' + query
            else:
                query_bytes = query
            s.send(bytes(query_bytes, 'utf-8') + b"\r\n")
            # recv returns bytes
            while True:
                d = s.recv(4096)
                response += d
                if not d:
                    break
            s.close()

            nhost = None
            response = response.decode('utf-8', 'replace')
            if 'with "=xxx"' in response:
                return self.whois(query, hostname, flags, True)
            if flags & NICClient.WHOIS_RECURSE and nhost is None:
                nhost = self.findwhois_server(response, hostname, query)
            if nhost is not None:
                response += self.whois(query, nhost, 0, quiet=True)
        except socket.error as exc:  # 'response' is assigned a value (also a str) even on socket timeout
            if not quiet:
                logger.error("Error trying to connect to %s: closing socket - %s", hostname, exc)
            s.close()
            response = "Socket not responding: {}".format(exc)
        return response

    @staticmethod
    def choose_server(domain):
        """Choose initial lookup NIC host"""
        try:
            domain = domain.encode('idna').decode('utf-8')
        except TypeError:
            domain = domain.decode('utf-8').encode('idna').decode('utf-8')
        except AttributeError:
            domain = domain.decode('utf-8').encode('idna').decode('utf-8')
        if domain.endswith("-NORID"):
            return NICClient.NORIDHOST
        if domain.endswith("id"):
            return NICClient.PANDIHOST
        if domain.endswith('.pp.ua'):
            return NICClient.PPUA_HOST

        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return None
        tld = domain_parts[-1]
        if tld[0].isdigit():
            return NICClient.ANICHOST

        if tld in NICClient.NO_WHOIS_SERVER:
            return None

        matching_tld = None
        server = None
        for whois_server, tlds in NICClient.WHOIS_SERVERS.items():
            for _tld in tlds:
                if domain.endswith('.' + _tld) and (not matching_tld or len(matching_tld) < len(_tld)):
                    matching_tld = _tld
                    server = whois_server
                    break

        if server:
            return server

        server = NICClient.QNICHOST_HEAD + tld
        try:
            socket.gethostbyname(server)
        except socket.gaierror:
            server = tld + NICClient.QNICHOST_TAIL
        return server

    def whois_lookup(self, options, query_arg, flags, quiet=False):
        """Main entry point: Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server, then if quick
        flag is false, perform a second lookup on the region-specific
        server for contact records.  If `quiet` is `True`, no message
        will be printed to STDOUT when a socket error is encountered."""
        nichost = None
        # whoud happen when this function is called by other than main
        if options is None:
            options = {}

        if ('whoishost' not in options or options['whoishost'] is None) \
                and ('country' not in options or options['country'] is None):
            self.use_qnichost = True
            options['whoishost'] = NICClient.NICHOST
            if not (flags & NICClient.WHOIS_QUICK) and query_arg.split('.')[-1] in NICClient.WHOIS_RECURSE_TLDS:
                flags |= NICClient.WHOIS_RECURSE

        if 'country' in options and options['country'] is not None:
            result = self.whois(
                query_arg,
                options['country'] + NICClient.QNICHOST_TAIL,
                flags,
                quiet=quiet,
            )
        elif self.use_qnichost:
            nichost = self.choose_server(query_arg)
            if nichost is not None:
                result = self.whois(query_arg, nichost, flags, quiet=quiet)
            else:
                result = ''
        else:
            result = self.whois(query_arg, options['whoishost'], flags, quiet=quiet)
        return result


def parse_command_line(argv):
    """Options handling mostly follows the UNIX whois(1) man page, except
    long-form options can also be used.
    """
    usage = "usage: %prog [options] name"

    parser = optparse.OptionParser(add_help_option=False, usage=usage)
    parser.add_option("-a", "--arin", action="store_const",
                      const=NICClient.ANICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.ANICHOST)
    parser.add_option("-A", "--apnic", action="store_const",
                      const=NICClient.PNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.PNICHOST)
    parser.add_option("-b", "--abuse", action="store_const",
                      const=NICClient.ABUSEHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.ABUSEHOST)
    parser.add_option("-c", "--country", action="store",
                      type="string", dest="country",
                      help="Lookup using country-specific NIC")
    parser.add_option("-d", "--mil", action="store_const",
                      const=NICClient.DNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.DNICHOST)
    parser.add_option("-g", "--gov", action="store_const",
                      const=NICClient.GNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.GNICHOST)
    parser.add_option("-h", "--host", action="store",
                      type="string", dest="whoishost",
                      help="Lookup using specified whois host")
    parser.add_option("-i", "--nws", action="store_const",
                      const=NICClient.INICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.INICHOST)
    parser.add_option("-I", "--iana", action="store_const",
                      const=NICClient.IANAHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.IANAHOST)
    parser.add_option("-l", "--lcanic", action="store_const",
                      const=NICClient.LNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.LNICHOST)
    parser.add_option("-m", "--ra", action="store_const",
                      const=NICClient.MNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.MNICHOST)
    parser.add_option("-p", "--port", action="store",
                      type="int", dest="port",
                      help="Lookup using specified tcp port")
    parser.add_option("-Q", "--quick", action="store_true",
                      dest="b_quicklookup",
                      help="Perform quick lookup")
    parser.add_option("-r", "--ripe", action="store_const",
                      const=NICClient.RNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.RNICHOST)
    parser.add_option("-R", "--ru", action="store_const",
                      const="ru", dest="country",
                      help="Lookup Russian NIC")
    parser.add_option("-6", "--6bone", action="store_const",
                      const=NICClient.SNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.SNICHOST)
    parser.add_option("-n", "--ina", action="store_const",
                      const=NICClient.PANDIHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.PANDIHOST)
    parser.add_option("-?", "--help", action="help")

    return parser.parse_args(argv)


if __name__ == "__main__":
    flags = 0
    nic_client = NICClient()
    options, args = parse_command_line(sys.argv)
    if options.b_quicklookup:
        flags = flags | NICClient.WHOIS_QUICK
    logger.debug(nic_client.whois_lookup(options.__dict__, args[1], flags))
