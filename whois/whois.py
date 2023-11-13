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
    WHOIS_BY_TLD = {
        "whois.nic.google": ['xn--q9jyb4c', 'meet', 'foo', 'soy', 'prod', 'how', 'mov', 'youtube', 'channel', 'boo', 'dad', 'new', 'eat', 'ing', 'meme', 'here', 'zip', 'day', 'gmail', 'fly', 'gbiz', 'rsvp', 'esq', 'xn--flw351e',
                        'xn--qcka1pmc', 'gle', 'cal', 'chrome', 'nexus', 'android', 'google', 'prof', 'guge', 'docs', 'dev', 'hangout', 'goog', 'dclk', 'ads', 'page', 'drive', 'play', 'app', 'map', 'search', 'phd'],
        "whois.tucowsregistry.net": ['sexy', 'tattoo', 'gift', 'link', 'country', 'hiphop', 'juegos', 'hiv', 'property', 'click', 'yandex', 'trust', 'love', 'creditunion', 'cloud'],
        "whois.identitydigital.services": ['xn--unup4y', 'ventures', 'equipment', 'singles', 'lighting', 'holdings', 'voyage', 'clothing', 'guru', 'bike', 'camera', 'construction', 'contractors', 'estate', 'gallery', 'graphics', 'land', 'plumbing', 'technology', 'diamonds', 'directory', 'enterprises', 'kitchen', 'photography', 'tips', 'today', 'immobilien', 'email', 'solutions', 'holiday', 'florist', 'coffee', 'builders', 'repair', 'ninja', 'kaufen', 'house', 'training', 'codes', 'international', 'onl', 'glass', 'education', 'farm', 'solar', 'institute', 'recipes', 'computer', 'academy', 'careers', 'cab', 'systems', 'domains', 'viajes', 'company', 'camp', 'limo', 'management', 'photos', 'shoes', 'center', 'support', 'agency', 'marketing', 'cheap', 'zone', 'pink', 'rich', 'red', 'shiksha', 'tools', 'cool', 'kim', 'watch', 'expert', 'works', 'tienda', 'bargains', 'boutique', 'community', 'dating', 'catering', 'cleaning', 'cruises', 'events', 'exposed', 'flights', 'partners', 'properties', 'rentals', 'report', 'blue', 'xn--6frz82g', 'vision', 'cards', 'foundation', 'condos', 'villas', 'parts', 'productions', 'maison', 'dance', 'moda', 'social', 'democrat', 'supplies', 'fish', 'vacations', 'industries', 'supply', 'voto', 'vote', 'xn--c1avg', 'xn--i1b6b1a6a2e', 'xn--nqv7fs00ema', 'xn--nqv7f', 'actor', 'pub', 'black', 'consulting', 'haus', 'vegas', 'archi', 'jetzt', 'reviews', 'futbol', 'rocks', 'pictures', 'university', 'associates', 'reisen', 'media', 'town', 'toys', 'lease', 'services', 'engineering', 'gripe', 'capital', 'frogans', 'limited', 'fail', 'exchange', 'tax', 'wtf', 'fund', 'surgery', 'investments', 'financial', 'gratis', 'furniture', 'dental', 'care', 'cash', 'discount', 'clinic', 'fitness', 'schule', 'creditcard', 'insure', 'finance', 'airforce', 'guide', 'loans', 'church', 'life', 'credit', 'accountants', 'digital', 'claims', 'reise', 'degree', 'bio', 'lawyer', 'vet', 'mortgage', 'software', 'market', 'dentist', 'attorney', 'engineer', 'rehab', 'republican', 'gives', 'navy', 'army', 'global', 'organic', 'lotto', 'green', 'city', 'deals', 'direct', 'place', 'active', 'healthcare', 'restaurant', 'gifts', 'sarl', 'auction', 'ngo', 'nra', 'lgbt', 'ong', 'pizza', 'immo', 'bnpparibas', 'xn--b4w605ferd', 'xn--czrs0t', 'xn--fjq720a', 'xn--vhquv', 'emerck', 'business', 'band', 'crs', 'cern', 'forsale', 'rip', 'network', 'dabur', 'ltda', 'scholarships', 'world', 'shriram', 'mormon', 'temasek', 'hermes', 'bnl', 'java', 'fan', 'lds', 'group', 'sew', 'abbott', 'oracle', 'irish', 'poker', 'ist', 'istanbul', 'ski', 'energy', 'delivery', 'ltd', 'obi', 'coach', 'sanofi', 'marriott', 'memorial', 'money', 'legal', 'video', 'sale', 'abb', 'redstone', 'ice', 'bms', 'zara', 'tires', 'giving', 'jaguar', 'landrover', 'stada', 'barclays', 'barclaycard', 'chat', 'bingo', 'style', 'tennis', 'live', 'dog', 'salon', 'xin', 'forex', 'apartments', 'trading', 'ubs', 'markets', 'broker', 'school', 'news', 'bradesco', 'promo', 'football', 'casino', 'golf', 'edeka', 'stockholm', 'fage', 'xn--5tzm5g', 'watches', 'xn--jlq61u9w7b', 'contact', 'avianca', 'nokia', 'star', 'alipay', 'alibaba', 'taobao', 'tmall', 'gold', 'tours', 'weir', 'helsinki', 'plus', 'movie', 'orientexpress', 'cafe', 'studio', 'hdfcbank', 'express', 'xn--estv75g', 'tvs', 'delta', 'gallup', 'cipriani', 'team', 'show', 'jewelry', 'weibo', 'xn--9krt00a', 'statebank', 'sbi', 'tatamotors', 'sina', 'theater', 'realty', 'run', 'taxi', 'hockey', 'redumbrella', 'travelers', 'travelersinsurance', 'soccer', 'trv', 'coupons', 'lasalle', 'jll', 'homedepot', 'viking', 'fyi', 'jio', 'bcg', 'ril', 'mba', 'family', 'reliance', 'thd', 'kerryproperties', 'chanel', 'ceb', 'kuokgroup', 'kerrylogistics', 'agakhan', 'akdn', 'shaw', 'jcp', 'kerryhotels', 'observer', 'bet', 'metlife', 'pet', 'srl', 'nowtv', 'extraspace', 'beats', 'apple', 'volkswagen', 'vig', 'xn--fzys8d69uvgm', 'hkt', 'pccw', 'richardli', 'dot', 'nikon', 'audi', 'games', 'ott', 'ollo', 'dtv', 'locker', 'lamborghini', 'barefoot', 'gallo', 'vin', 'next', 'wine', 'bosch', 'nextdirect', 'rexroth', 'lipsy', 'ups', 'xn--3oq18vl8pn36a', 'mit', 'dunlop', 'goodyear', 'pnc', 'boehringer', 'itv', 'ericsson', 'lefrak', 'esurance', 'bugatti', 'bbt', 'citadel', 'progressive', 'samsclub', 'mckinsey', 'fiat', 'hughes', 'lancia', 'george', 'latino', 'alfaromeo', 'allstate', 'ferrari', 'blockbuster', 'goodhands', 'sling', 'hdfc', 'asda', 'bestbuy', 'chrysler', 'dodge', 'maserati', 'uconnect', 'juniper', 'walmart', 'abarth', 'mopar', 'jeep', 'srt', 'dish', 'fidelity', 'imamat', 'showtime', 'wolterskluwer', 'fedex', 'ismaili', 'cbs', 'lundbeck', 'aigo', 'rogers', 'fido', 'ubank', 'nab', 'kosher', 'vanguard', 'shangrila', 'caseih', 'iveco', 'newholland', 'aol', 'lamer', 'origins', 'clinique', 'pwc', 'volvo', 'cruise', 'gmbh', 'shopping', 'doctor', 'mobile', 'data', 'phone', 'grocery', 'dvr', 'hospital', 'llc', 'charity', 'spa', 'kids']
    }

    ABUSEHOST = "whois.abuse.net"
    AI_HOST = "whois.nic.ai"
    ANICHOST = "whois.arin.net"
    AR_HOST = "whois.nic.ar"
    BNICHOST = "whois.registro.br"
    BY_HOST = "whois.cctld.by"
    CA_HOST = "whois.ca.fury.ca"
    CHAT_HOST = "whois.nic.chat"
    CL_HOST = "whois.nic.cl"
    CR_HOST = "whois.nic.cr"
    DEFAULT_PORT = "nicname"
    DENICHOST = "whois.denic.de"
    DE_HOST = "whois.denic.de"
    DK_HOST = "whois.dk-hostmaster.dk"
    DNICHOST = "whois.nic.mil"
    DO_HOST = "whois.nic.do"
    GAMES_HOST = "whois.nic.games"
    GNICHOST = "whois.nic.gov"
    GROUP_HOST = 'whois.namecheap.com'
    HK_HOST = "whois.hkirc.hk"
    HN_HOST = "whois.nic.hn"
    HR_HOST = "whois.dns.hr"
    IANAHOST = "whois.iana.org"
    INICHOST = "whois.networksolutions.com"
    IST_HOST = "whois.afilias-srs.net"
    JOBS_HOST = "whois.nic.jobs"
    JP_HOST = 'whois.jprs.jp'
    KZ_HOST = "whois.nic.kz"
    LAT_HOST = "whois.nic.lat"
    MA_HOST = "whois.registre.ma"
    LI_HOST = "whois.nic.li"
    LNICHOST = "whois.lacnic.net"
    LT_HOST = 'whois.domreg.lt'
    MARKET_HOST = "whois.nic.market"
    MNICHOST = "whois.ra.net"
    MONEY_HOST = "whois.nic.money"
    MX_HOST = "whois.mx"
    NICHOST = "whois.crsnic.net"
    NL_HOST = 'whois.domain-registry.nl'
    NORIDHOST = "whois.norid.no"
    ONLINE_HOST = "whois.nic.online"
    OOO_HOST = "whois.nic.ooo"
    PAGE_HOST = "whois.nic.page"
    PANDIHOST = "whois.pandi.or.id"
    PE_HOST = "kero.yachay.pe"
    PNICHOST = "whois.apnic.net"
    QNICHOST_TAIL = ".whois-servers.net"
    QNICHOST_HEAD = "whois.nic."
    RNICHOST = "whois.ripe.net"
    SNICHOST = "whois.6bone.net"
    WEBSITE_HOST = "whois.nic.website"
    ZA_HOST = "whois.registry.net.za"
    RU_HOST = "whois.tcinet.ru"
    CITY_HOST = "whois.nic.city"
    DESIGN_HOST = "whois.nic.design"
    NAME_HOST = "whois.name.com"
    STYLE_HOST = "whois.nic.style"
    GDD_HOST = "whois.dnrs.godaddy"
    SHOP_HOST = "whois.nic.shop"
    STORE_HOST = "whois.centralnic.com"
    DETI_HOST = "whois.nic.xn--d1acj3b"
    MOSKVA_HOST = "whois.registry.nic.xn--80adxhks"
    RF_HOST = "whois.registry.tcinet.ru"
    PIR_HOST = "whois.publicinterestregistry.org"
    NG_HOST = "whois.nic.net.ng"
    PPUA_HOST = "whois.pp.ua"
    UKR_HOST = "whois.dotukr.com"
    EDU_HOST = 'whois.educause.edu'
    ES_HOST = IANAHOST
    SITE_HOST = "whois.nic.site"
    TRAINING_HOST = "whois.nic.training"

    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois = [LNICHOST, RNICHOST, PNICHOST, BNICHOST, PANDIHOST]

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

            if hostname == NICClient.DENICHOST:
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
                logger.error("Error trying to connect to socket: closing socket - {}".format(exc))
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
        if domain.endswith("hr"):
            return NICClient.HR_HOST
        if domain.endswith('.pp.ua'):
            return NICClient.PPUA_HOST

        domain = domain.split('.')
        if len(domain) < 2:
            return None
        tld = domain[-1]
        if tld[0].isdigit():
            return NICClient.ANICHOST

        for host, tlds in NICClient.WHOIS_BY_TLD.items():
            if tld in tlds:
                return host

        if tld == 'ai':
            return NICClient.AI_HOST
        elif tld == 'ar':
            return NICClient.AR_HOST
        elif tld == 'by':
            return NICClient.BY_HOST
        elif tld == 'bn':
            return 'whois.bnnic.bn'
        elif tld == 'ca':
            return NICClient.CA_HOST
        elif tld == 'qa':
            return 'whois.registry.qa'
        elif tld == 'chat':
            return NICClient.CHAT_HOST
        elif tld == 'ma':
            return NICClient.MA_HOST
        elif tld == 'cl':
            return NICClient.CL_HOST
        elif tld == 'cr':
            return NICClient.CR_HOST
        elif tld == 'de':
            return NICClient.DE_HOST
        elif tld == 'do':
            return NICClient.DO_HOST
        elif tld == 'edu':
            return NICClient.EDU_HOST
        elif tld == 'games':
            return NICClient.GAMES_HOST
        elif tld == 'group':
            return "whois.nic.group"
        elif tld == 'es':
            return NICClient.ES_HOST
        elif tld == 'nc':
            return 'whois.nc'
        elif tld == 'group':
            return NICClient.GROUP_HOST
        elif tld == 'hk':
            return NICClient.HK_HOST
        elif tld == 'hn':
            return NICClient.HN_HOST
        elif tld == 'ist':
            return NICClient.IST_HOST
        elif tld == 'jobs':
            return NICClient.JOBS_HOST
        elif tld == 'cc':
            return 'ccwhois.verisign-grs.com'
        elif tld == 'sn':
            return 'whois.nic.sn'
        elif tld == 'jp':
            return NICClient.JP_HOST
        elif tld == 'kz':
            return NICClient.KZ_HOST
        elif tld == 'lb':
            return 'whois.lbdr.org.lb'
        elif tld == 'ge':
            return 'whois.nic.ge'
        elif tld == 'lat':
            return NICClient.LAT_HOST
        elif tld == 'li':
            return NICClient.LI_HOST
        elif tld == 'lt':
            return NICClient.LT_HOST
        elif tld == 'market':
            return NICClient.MARKET_HOST
        elif tld == 'money':
            return NICClient.MONEY_HOST
        elif tld == 'mx':
            return NICClient.MX_HOST
        elif tld == 'nl':
            return NICClient.NL_HOST
        elif tld == 'online':
            return NICClient.ONLINE_HOST
        elif tld == 'ooo':
            return NICClient.OOO_HOST
        elif tld == 'pe':
            return NICClient.PE_HOST
        elif tld == 'pf':
            return 'whois.registry.pf'
        elif tld == 'website':
            return NICClient.WEBSITE_HOST
        elif tld == 'za':
            return NICClient.ZA_HOST
        elif tld == 'fj':
            return 'www.whois.fj'
        elif tld == 'ru':
            return NICClient.RU_HOST
        elif tld == 'sg':
            return 'whois.sgnic.sg'
        elif tld == 'tz':
            return 'whois.tznic.or.tz'
        elif tld == 'mo':
            return 'whois.monic.mo'
        elif tld == 'my':
            return 'whois.mynic.my'
        elif tld == 'tn':
            return 'whois.ati.tn'
        elif tld == 'tv':
            return 'whois.nic.tv'
        elif tld == 'bz':
            return 'whois.rrpproxy.net'
        elif tld == 'ky':
            return 'whois.uniregistrar.com'
        elif tld == 'mw':
            return 'whois.nic.mw'
        elif tld == 'city':
            return NICClient.CITY_HOST
        elif tld == 'design':
            return NICClient.DESIGN_HOST
        elif tld == 'studio':
            return 'whois.nic.studio'
        elif tld == 'style':
            return NICClient.STYLE_HOST
        elif tld == 'mk':
            return 'whois.marnet.mk'
        elif tld == 'su':
            return NICClient.RU_HOST
        elif tld == 'pk':
            return 'whois.pknic.net.pk'
        elif tld == 'рус' or tld == 'xn--p1acf':
            return NICClient.RU_HOST
        elif tld == 'direct':
            return NICClient.GDD_HOST
        elif tld == 'vip':
            return NICClient.GDD_HOST
        elif tld == 'shop':
            return NICClient.SHOP_HOST
        elif tld == 'store':
            return NICClient.STORE_HOST
        elif tld == 'дети' or tld == 'xn--d1acj3b':
            return NICClient.DETI_HOST
        elif tld == 'москва' or tld == 'xn--80adxhks':
            return NICClient.MOSKVA_HOST
        elif tld == 'рф' or tld == 'xn--p1ai':
            return NICClient.RF_HOST
        elif tld == 'орг' or tld == 'xn--c1avg':
            return NICClient.PIR_HOST
        elif tld == 'ng':
            return NICClient.NG_HOST
        elif tld == 'om':
            return 'whois.registry.om'
        elif tld == 'укр' or tld == 'xn--j1amh':
            return NICClient.UKR_HOST
        elif tld == 'training':
            return NICClient.TRAINING_HOST
        elif tld == "site":
            return NICClient.SITE_HOST
        else:
            server = tld + NICClient.QNICHOST_TAIL
            try:
                socket.gethostbyname(server)
            except socket.gaierror:
                server = NICClient.QNICHOST_HEAD + tld
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
            if not (flags & NICClient.WHOIS_QUICK):
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
    flags = 0

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
