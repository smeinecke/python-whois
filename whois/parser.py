# -*- coding: utf-8 -*-

# parser.py - Module for parsing whois response data
# Copyright (c) 2008 Andrey Petrov
#
# This module is part of python-whois and is released under
# the MIT license: http://www.opensource.org/licenses/mit-license.php

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import json
import logging
import re
from builtins import *
from datetime import datetime
from inspect import isfunction
import sys

from future import standard_library
from past.builtins import basestring

logger = logging.getLogger(__name__)

standard_library.install_aliases()

try:
    import dateutil.parser as dp
    from .time_zones import tz_data

    DATEUTIL = True
except ImportError:
    DATEUTIL = False

EMAIL_REGEX = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[" \
              r"a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\s?"

KNOWN_FORMATS = [
    '%d-%b-%Y',  # 02-jan-2000
    '%d-%B-%Y',  # 11-February-2000
    '%d-%m-%Y',  # 20-10-2000
    '%Y-%m-%d',  # 2000-01-02
    '%d.%m.%Y',  # 2.1.2000
    '%Y.%m.%d',  # 2000.01.02
    '%Y/%m/%d',  # 2000/01/02
    '%Y/%m/%d %H:%M:%S',  # 2011/06/01 01:05:01
    '%Y/%m/%d %H:%M:%S (%z)',  # 2011/06/01 01:05:01 (+0900)
    '%Y%m%d',  # 20170209
    '%Y%m%d %H:%M:%S',  # 20110908 14:44:51
    '%d/%m/%Y',  # 02/01/2013
    '%Y. %m. %d.',  # 2000. 01. 02.
    '%Y.%m.%d %H:%M:%S',  # 2014.03.08 10:28:24
    '%d-%b-%Y %H:%M:%S %Z',  # 24-Jul-2009 13:20:03 UTC
    '%a %b %d %H:%M:%S %Z %Y',  # Tue Jun 21 23:59:59 GMT 2011
    '%a %b %d %Y',  # Tue Dec 12 2000
    '%Y-%m-%dT%H:%M:%S',  # 2007-01-26T19:10:31
    '%Y-%m-%dT%H:%M:%SZ',  # 2007-01-26T19:10:31Z
    '%Y-%m-%dT%H:%M:%SZ[%Z]',  # 2007-01-26T19:10:31Z[UTC]
    '%Y-%m-%dT%H:%M:%S.%fZ',  # 2018-12-01T16:17:30.568Z
    '%Y-%m-%dT%H:%M:%S.%f%z',  # 2011-09-08T14:44:51.622265+03:00
    '%Y-%m-%dT%H:%M:%S%z',  # 2013-12-06T08:17:22-0800
    '%Y-%m-%dT%H:%M:%S%zZ',  # 1970-01-01T02:00:00+02:00Z
    '%Y-%m-%dt%H:%M:%S.%f',  # 2011-09-08t14:44:51.622265
    '%Y-%m-%dt%H:%M:%S',  # 2007-01-26T19:10:31
    '%Y-%m-%dt%H:%M:%SZ',  # 2007-01-26T19:10:31Z
    '%Y-%m-%dt%H:%M:%S.%fz',  # 2007-01-26t19:10:31.00z
    '%Y-%m-%dt%H:%M:%S%z',  # 2011-03-30T19:36:27+0200
    '%Y-%m-%dt%H:%M:%S.%f%z',  # 2011-09-08T14:44:51.622265+03:00
    '%Y-%m-%d %H:%M:%SZ',  # 2000-08-22 18:55:20Z
    '%Y-%m-%d %H:%M:%S',  # 2000-08-22 18:55:20
    '%d %b %Y %H:%M:%S',  # 08 Apr 2013 05:44:00
    '%d/%m/%Y %H:%M:%S',  # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S %Z',  # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S.%f %Z',  # 23/04/2015 12:00:07.619546 EEST
    '%B %d %Y',  # August 14 2017
    '%d.%m.%Y %H:%M:%S',  # 08.03.2014 10:28:24
    'before %b-%Y',  # before aug-1996
    '%Y-%m-%d %H:%M:%S (%Z%z)',  # 2017-09-26 11:38:29 (GMT+00:00)
    '%Y-%m-%d %H:%M:%S (%Z+0:00)',  # 2018-06-21 17:17:59 (GMT+0:00)
]

WHOIS_BY_TLD = {
    "WhoisGoogle": [
        "ads",
        "android",
        "app",
        "boo",
        "cal",
        "channel",
        "chrome",
        "dad",
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
    "WhoisTucows": [
        "click",
        "cloud",
        "country",
        "creditunion",
        "gift",
        "hiphop",
        "hiv",
        "juegos",
        "link",
        "love",
        "property",
        "sexy",
        "tattoo",
        "trust",
        "yandex",
    ],
    "WhoisIdentityDigitalInc": [
        "abarth",
        "abb",
        "abbott",
        "academy",
        "accountants",
        "active",
        "actor",
        "agakhan",
        "agency",
        "aigo",
        "airforce",
        "akdn",
        "alfaromeo",
        "alibaba",
        "alipay",
        "allstate",
        "aol",
        "apartments",
        "apple",
        "archi",
        "army",
        "asda",
        "associates",
        "attorney",
        "auction",
        "audi",
        "avianca",
        "band",
        "barclaycard",
        "barclays",
        "barefoot",
        "bargains",
        "bbt",
        "bcg",
        "beats",
        "bestbuy",
        "bet",
        "bike",
        "bingo",
        "bio",
        "black",
        "blockbuster",
        "blue",
        "bms",
        "bnl",
        "bnpparibas",
        "boehringer",
        "bosch",
        "boutique",
        "bradesco",
        "broker",
        "bugatti",
        "builders",
        "business",
        "cab",
        "cafe",
        "camera",
        "camp",
        "capital",
        "cards",
        "care",
        "careers",
        "caseih",
        "cash",
        "casino",
        "catering",
        "cbs",
        "ceb",
        "center",
        "cern",
        "chanel",
        "charity",
        "chat",
        "cheap",
        "chrysler",
        "church",
        "cipriani",
        "citadel",
        "city",
        "claims",
        "cleaning",
        "clinic",
        "clinique",
        "clothing",
        "coach",
        "codes",
        "coffee",
        "community",
        "company",
        "computer",
        "condos",
        "construction",
        "consulting",
        "contact",
        "contractors",
        "cool",
        "coupons",
        "credit",
        "creditcard",
        "crs",
        "cruise",
        "cruises",
        "dabur",
        "dance",
        "data",
        "dating",
        "deals",
        "degree",
        "delivery",
        "delta",
        "democrat",
        "dental",
        "dentist",
        "diamonds",
        "digital",
        "direct",
        "directory",
        "discount",
        "dish",
        "doctor",
        "dodge",
        "dog",
        "domains",
        "dot",
        "dtv",
        "dunlop",
        "dvr",
        "edeka",
        "education",
        "email",
        "emerck",
        "energy",
        "engineer",
        "engineering",
        "enterprises",
        "equipment",
        "ericsson",
        "estate",
        "esurance",
        "events",
        "exchange",
        "expert",
        "exposed",
        "express",
        "extraspace",
        "fage",
        "fail",
        "family",
        "fan",
        "farm",
        "fedex",
        "ferrari",
        "fiat",
        "fidelity",
        "fido",
        "finance",
        "financial",
        "fish",
        "fitness",
        "flights",
        "florist",
        "football",
        "forex",
        "forsale",
        "foundation",
        "frogans",
        "fund",
        "furniture",
        "futbol",
        "fyi",
        "gallery",
        "gallo",
        "gallup",
        "games",
        "george",
        "gifts",
        "gives",
        "giving",
        "glass",
        "global",
        "gmbh",
        "gold",
        "golf",
        "goodhands",
        "goodyear",
        "graphics",
        "gratis",
        "green",
        "gripe",
        "grocery",
        "group",
        "guide",
        "guru",
        "haus",
        "hdfc",
        "hdfcbank",
        "healthcare",
        "helsinki",
        "hermes",
        "hkt",
        "hockey",
        "holdings",
        "holiday",
        "homedepot",
        "hospital",
        "house",
        "hughes",
        "ice",
        "imamat",
        "immo",
        "immobilien",
        "industries",
        "institute",
        "insure",
        "international",
        "investments",
        "irish",
        "ismaili",
        "ist",
        "istanbul",
        "itv",
        "iveco",
        "jaguar",
        "java",
        "jcp",
        "jeep",
        "jetzt",
        "jewelry",
        "jio",
        "jll",
        "juniper",
        "kaufen",
        "kerryhotels",
        "kerrylogistics",
        "kerryproperties",
        "kids",
        "kim",
        "kitchen",
        "kosher",
        "kuokgroup",
        "lamborghini",
        "lamer",
        "lancia",
        "land",
        "landrover",
        "lasalle",
        "latino",
        "lawyer",
        "lds",
        "lease",
        "lefrak",
        "legal",
        "lgbt",
        "life",
        "lighting",
        "limited",
        "limo",
        "lipsy",
        "live",
        "llc",
        "loans",
        "locker",
        "lotto",
        "ltd",
        "ltda",
        "lundbeck",
        "maison",
        "management",
        "market",
        "marketing",
        "markets",
        "marriott",
        "maserati",
        "mba",
        "mckinsey",
        "media",
        "memorial",
        "metlife",
        "mit",
        "mobile",
        "moda",
        "money",
        "mopar",
        "mormon",
        "mortgage",
        "movie",
        "nab",
        "navy",
        "network",
        "newholland",
        "news",
        "next",
        "nextdirect",
        "ngo",
        "nikon",
        "ninja",
        "nokia",
        "nowtv",
        "nra",
        "obi",
        "observer",
        "ollo",
        "ong",
        "onl",
        "oracle",
        "organic",
        "orientexpress",
        "origins",
        "ott",
        "partners",
        "parts",
        "pccw",
        "pet",
        "phone",
        "photography",
        "photos",
        "pictures",
        "pink",
        "pizza",
        "place",
        "plumbing",
        "plus",
        "pnc",
        "poker",
        "productions",
        "progressive",
        "promo",
        "properties",
        "pub",
        "pwc",
        "realty",
        "recipes",
        "red",
        "redstone",
        "redumbrella",
        "rehab",
        "reise",
        "reisen",
        "reliance",
        "rentals",
        "repair",
        "report",
        "republican",
        "restaurant",
        "reviews",
        "rexroth",
        "rich",
        "richardli",
        "ril",
        "rip",
        "rocks",
        "rogers",
        "run",
        "sale",
        "salon",
        "samsclub",
        "sanofi",
        "sarl",
        "sbi",
        "scholarships",
        "school",
        "schule",
        "services",
        "sew",
        "shangrila",
        "shaw",
        "shiksha",
        "shoes",
        "shopping",
        "show",
        "showtime",
        "shriram",
        "sina",
        "singles",
        "ski",
        "sling",
        "soccer",
        "social",
        "software",
        "solar",
        "solutions",
        "spa",
        "srl",
        "srt",
        "stada",
        "star",
        "statebank",
        "stockholm",
        "studio",
        "style",
        "supplies",
        "supply",
        "support",
        "surgery",
        "systems",
        "taobao",
        "tatamotors",
        "tax",
        "taxi",
        "team",
        "technology",
        "temasek",
        "tennis",
        "thd",
        "theater",
        "tienda",
        "tips",
        "tires",
        "tmall",
        "today",
        "tools",
        "tours",
        "town",
        "toys",
        "trading",
        "training",
        "travelers",
        "travelersinsurance",
        "trv",
        "tvs",
        "ubank",
        "ubs",
        "uconnect",
        "university",
        "ups",
        "vacations",
        "vanguard",
        "vegas",
        "ventures",
        "vet",
        "viajes",
        "video",
        "vig",
        "viking",
        "villas",
        "vin",
        "vision",
        "volkswagen",
        "volvo",
        "vote",
        "voto",
        "voyage",
        "walmart",
        "watch",
        "watches",
        "weibo",
        "weir",
        "wine",
        "wolterskluwer",
        "works",
        "world",
        "wtf",
        "xin",
        "xn--3oq18vl8pn36a",
        "xn--5tzm5g",
        "xn--6frz82g",
        "xn--9krt00a",
        "xn--b4w605ferd",
        "xn--c1avg",
        "xn--czrs0t",
        "xn--estv75g",
        "xn--fjq720a",
        "xn--fzys8d69uvgm",
        "xn--i1b6b1a6a2e",
        "xn--jlq61u9w7b",
        "xn--nqv7f",
        "xn--nqv7fs00ema",
        "xn--unup4y",
        "xn--vhquv",
        "zara",
        "zone",
    ],
    "WhoisCentralNic": [
        "adac",
        "allfinanz",
        "art",
        "audio",
        "auto",
        "autos",
        "baby",
        "bar",
        "beauty",
        "best",
        "blog",
        "bmw",
        "boats",
        "bond",
        "box",
        "build",
        "cam",
        "car",
        "cars",
        "case",
        "ceo",
        "cfd",
        "christmas",
        "college",
        "cyou",
        "dealer",
        "deloitte",
        "dhl",
        "diet",
        "dvag",
        "epost",
        "etisalat",
        "fans",
        "feedback",
        "flowers",
        "flsmidth",
        "forum",
        "fresenius",
        "frl",
        "fun",
        "game",
        "gent",
        "guitars",
        "hair",
        "help",
        "homes",
        "host",
        "hosting",
        "icu",
        "inc",
        "kfh",
        "kpn",
        "kred",
        "lat",
        "lidl",
        "llp",
        "lol",
        "london",
        "lpl",
        "lplfinancial",
        "luxury",
        "makeup",
        "meo",
        "mini",
        "mom",
        "monster",
        "motorcycles",
        "music",
        "online",
        "ooo",
        "pics",
        "pid",
        "pohl",
        "press",
        "protection",
        "qpon",
        "quest",
        "reit",
        "rent",
        "rest",
        "ruhr",
        "saarland",
        "sapo",
        "sbs",
        "schwarz",
        "security",
        "sfr",
        "site",
        "skin",
        "smart",
        "space",
        "spiegel",
        "spreadbetting",
        "stc",
        "stcgroup",
        "storage",
        "store",
        "tech",
        "theatre",
        "tickets",
        "tui",
        "uno",
        "viva",
        "website",
        "wme",
        "xn--4gbrim",
        "xn--mgbaakc7dvf",
        "xn--ngbe9e0a",
        "xn--vermgensberater-ctb",
        "xn--vermgensberatung-pwb",
        "xyz",
        "yachts",
        "zuerich",
    ],
}


class PywhoisError(Exception):
    pass


def datetime_parse(s):
    for known_format in KNOWN_FORMATS:
        try:
            s = datetime.strptime(s, known_format)
            break
        except ValueError:
            pass  # Wrong format, keep trying
    return s


def cast_date(s, dayfirst=False, yearfirst=False):
    """Convert any date string found in WHOIS to a datetime object."""
    if DATEUTIL:
        try:
            return dp.parse(
                s,
                tzinfos=tz_data,
                dayfirst=dayfirst,
                yearfirst=yearfirst
            ).replace(tzinfo=None)
        except Exception:
            return datetime_parse(s)
    else:
        return datetime_parse(s)


class WhoisEntry(dict):
    """Base class for parsing a Whois entries."""
    # regular expressions to extract domain data from whois profile
    # child classes will override this
    _regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'whois_server': r'Whois Server: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'referral_url': r'Referral URL: *(.+)',  # http url of whois_server
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Expir\w+ Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'status': r'Status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email s
        'dnssec': r'dnssec: *([\S]+)',
        'name': r'Registrant Name: *(.+)',
        'org': r'Registrant\s*Organization: *(.+)',
        'address': r'Registrant Street: *(.+)',
        'city': r'Registrant City: *(.+)',
        'state': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'country': r'Registrant Country: *(.+)',
    }
    dayfirst = False
    yearfirst = False

    def __init__(self, domain, text, regex=None):
        if 'This TLD has no whois server, but you can access the whois database at' in text:
            raise PywhoisError(text)
        else:
            self.domain = domain
            self.text = text
            if regex is not None:
                self._regex = regex
                self._regex['emails'] = EMAIL_REGEX
            self.parse()

    def parse(self):
        """The first time an attribute is called it will be calculated here.
        The attribute is then set to be accessed directly by subsequent calls.
        """
        for attr, regex in list(self._regex.items()):
            if regex and isinstance(regex, str):
                values = []
                for data in re.findall(regex, self.text, re.IGNORECASE | re.M):

                    matches = data if isinstance(data, tuple) else [data]
                    for value in matches:
                        value = self._preprocess(attr, value)
                        if value and value not in values:
                            # avoid duplicates
                            values.append(value)
                if values and attr in ('registrar', 'whois_server', 'referral_url'):
                    values = values[-1]  # ignore junk
                if len(values) == 1:
                    values = values[0]
                elif not values:
                    values = None

                self[attr] = values
            elif regex and isfunction(regex):
                for attribute, value in regex(self.text).items():
                    self[attribute] = value

    def _preprocess(self, attr, value):
        value = value.strip()
        if value and isinstance(value, basestring) and not value.isdigit() and '_date' in attr:
            # try casting to date format
            value = cast_date(
                value,
                dayfirst=self.dayfirst,
                yearfirst=self.yearfirst)
        return value

    @staticmethod
    def parse_indented_registrant(text):
        pattern = re.compile(r'Registrant:(?:\s*[\r\n]+)*\s+([^\r\n]+)', re.MULTILINE)
        first_match = pattern.search(text)
        if first_match:
            registrant_name = first_match.group(1)
            return {"registrant_name": registrant_name}
        return {}

    @staticmethod
    def parse_indented_nameservers(text):
        pattern = re.compile(r'^\s+([\w.-]+)(?=\s*[\r\n]+|$)', re.MULTILINE)
        name_servers_section_match = re.search(r'Name Servers:(?:\s*[\r\n]+)*(.*)', text, re.DOTALL | re.IGNORECASE)

        name_servers = list()
        if name_servers_section_match:
            name_servers_section = name_servers_section_match.group(1)
            name_servers_found = pattern.findall(name_servers_section)
            for name_server in name_servers_found:
                name_servers.append(name_server.strip())
        return {"name_servers": name_servers}

    def __setitem__(self, name, value):
        super(WhoisEntry, self).__setitem__(name, value)

    def __getattr__(self, name):
        return self.get(name)

    def __str__(self):
        def handler(e): return str(e)

        return json.dumps(self, indent=2, default=handler)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__ = state

    @staticmethod
    def load(domain, text):
        """Given whois output in ``text``, return an instance of ``WhoisEntry``
        that represents its parsed contents.
        """
        if text.strip() == 'No whois server is known for this kind of object.':
            raise PywhoisError(text)

        tld = domain.split('.')[-1] if '.' in domain else None

        for fnc, tld_list in WHOIS_BY_TLD.items():
            if tld in tld_list:
                return getattr(sys.modules[__name__], fnc)(domain, text)

        if domain.endswith('.com'):
            return WhoisCom(domain, text)
        elif domain.endswith('.net'):
            return WhoisNet(domain, text)
        elif domain.endswith('.org'):
            return WhoisOrg(domain, text)
        elif domain.endswith('.edu'):
            return WhoisEdu(domain, text)
        elif domain.endswith('.gov'):
            return WhoisGov(domain, text)
        elif domain.endswith('.name'):
            return WhoisName(domain, text)
        elif domain.endswith('.me'):
            return WhoisMe(domain, text)
        elif domain.endswith('.ae'):
            return WhoisAe(domain, text)
        elif domain.endswith('.au'):
            return WhoisAU(domain, text)
        elif domain.endswith('.am'):
            return WhoisAM(domain, text)
        elif domain.endswith('.ru'):
            return WhoisRu(domain, text)
        elif domain.endswith('.tz'):
            return WhoisTz(domain, text)
        elif domain.endswith('.rs'):
            return WhoisRs(domain, text)
        elif domain.endswith('.us'):
            return WhoisUs(domain, text)
        elif domain.endswith('.uk'):
            return WhoisUk(domain, text)
        elif domain.endswith('.qa'):
            return WhoisQa(domain, text)
        elif domain.endswith('.so'):
            return WhoisSo(domain, text)
        elif domain.endswith('.fr') or domain.endswith('.pm'):
            return WhoisFr(domain, text)
        elif domain.endswith('.nl'):
            return WhoisNl(domain, text)
        elif domain.endswith('.mo'):
            return WhoisMo(domain, text)
        elif domain.endswith('.lt'):
            return WhoisLt(domain, text)
        elif domain.endswith('.fi'):
            return WhoisFi(domain, text)
        elif domain.endswith('.hr'):
            return WhoisHr(domain, text)
        elif domain.endswith('.bn'):
            return WhoisBn(domain, text)
        elif domain.endswith('.hn'):
            return WhoisHn(domain, text)
        elif domain.endswith('.hu'):
            return WhoisHu(domain, text)
        elif domain.endswith('.hk'):
            return WhoisHk(domain, text)
        elif domain.endswith('.jp'):
            return WhoisJp(domain, text)
        elif domain.endswith('.pl'):
            return WhoisPl(domain, text)
        elif domain.endswith('.br'):
            return WhoisBr(domain, text)
        elif domain.endswith('.th'):
            return WhoisTh(domain, text)
        elif domain.endswith('.eu'):
            return WhoisEu(domain, text)
        elif domain.endswith('.ee'):
            return WhoisEe(domain, text)
        elif domain.endswith('.kr'):
            return WhoisKr(domain, text)
        elif domain.endswith('.pt'):
            return WhoisPt(domain, text)
        elif domain.endswith('.bg'):
            return WhoisBg(domain, text)
        elif domain.endswith('.de'):
            return WhoisDe(domain, text)
        elif domain.endswith('.at'):
            return WhoisAt(domain, text)
        elif domain.endswith('.ca'):
            return WhoisCa(domain, text)
        elif domain.endswith('.be'):
            return WhoisBe(domain, text)
        elif domain.endswith('.рф'):
            return WhoisRf(domain, text)
        elif domain.endswith('.info'):
            return WhoisInfo(domain, text)
        elif domain.endswith('.su'):
            return WhoisSu(domain, text)
        elif domain.endswith('.si'):
            return WhoisSi(domain, text)
        elif domain.endswith('.kg'):
            return WhoisKg(domain, text)
        elif domain.endswith('.io'):
            return WhoisIo(domain, text)
        elif domain.endswith('.biz'):
            return WhoisBiz(domain, text)
        elif domain.endswith('.cc'):
            return WhoisCc(domain, text)
        elif domain.endswith('.mobi'):
            return WhoisMobi(domain, text)
        elif domain.endswith('.fj'):
            return WhoisFj(domain, text)
        elif domain.endswith('.ch'):
            return WhoisChLi(domain, text)
        elif domain.endswith('.sn'):
            return WhoisSn(domain, text)
        elif domain.endswith('.pf'):
            return WhoisPf(domain, text)
        elif domain.endswith('.li'):
            return WhoisChLi(domain, text)
        elif domain.endswith('.id'):
            return WhoisID(domain, text)
        elif domain.endswith('.as') or domain.endswith('.gg') or domain.endswith('.je'):
            return WhoisAsGgJe(domain, text)
        elif domain.endswith('.sk'):
            return WhoisSK(domain, text)
        elif domain.endswith('.se'):
            return WhoisSe(domain, text)
        elif domain.endswith('.no'):
            return WhoisNo(domain, text)
        elif domain.endswith('.nu'):
            return WhoisSe(domain, text)
        elif domain.endswith('.is'):
            return WhoisIs(domain, text)
        elif domain.endswith('.dk'):
            return WhoisDk(domain, text)
        elif domain.endswith('.it'):
            return WhoisIt(domain, text)
        elif domain.endswith('.mx'):
            return WhoisMx(domain, text)
        elif domain.endswith('.mw'):
            return WhoisMw(domain, text)
        elif domain.endswith('.ai'):
            return WhoisAi(domain, text)
        elif domain.endswith('.il'):
            return WhoisIl(domain, text)
        elif domain.endswith('.in'):
            return WhoisIn(domain, text)
        elif domain.endswith('.cat'):
            return WhoisCat(domain, text)
        elif domain.endswith('.ie'):
            return WhoisIe(domain, text)
        elif domain.endswith('.nz'):
            return WhoisNz(domain, text)
        elif domain.endswith('.lu'):
            return WhoisLu(domain, text)
        elif domain.endswith('.cz'):
            return WhoisCz(domain, text)
        elif domain.endswith('.cn'):
            return WhoisCn(domain, text)
        elif domain.endswith('.tn'):
            return WhoisTn(domain, text)
        elif domain.endswith('.cl'):
            return WhoisCl(domain, text)
        elif domain.endswith('.ar'):
            return WhoisAr(domain, text)
        elif domain.endswith('.by'):
            return WhoisBy(domain, text)
        elif domain.endswith('.cr'):
            return WhoisCr(domain, text)
        elif domain.endswith('.do'):
            return WhoisDo(domain, text)
        elif domain.endswith('.jobs'):
            return WhoisJobs(domain, text)
        elif domain.endswith('.pe'):
            return WhoisPe(domain, text)
        elif domain.endswith('.ro'):
            return WhoisRo(domain, text)
        elif domain.endswith('.sa'):
            return WhoisSa(domain, text)
        elif domain.endswith('.tw'):
            return WhoisTw(domain, text)
        elif domain.endswith('.tr'):
            return WhoisTr(domain, text)
        elif domain.endswith('.ve'):
            return WhoisVe(domain, text)
        elif domain.endswith('.ua'):
            if domain.endswith('.pp.ua'):
                return WhoisPpUa(domain, text)
            return WhoisUA(domain, text)
        elif domain.endswith('.укр') or domain.endswith('.xn--j1amh'):
            return WhoisUkr(domain, text)
        elif domain.endswith('.kz'):
            return WhoisKZ(domain, text)
        elif domain.endswith('.ir'):
            return WhoisIR(domain, text)
        elif domain.endswith('.中国'):
            return WhoisZhongGuo(domain, text)
        elif domain.endswith('.sg'):
            return WhoisSg(domain, text)
        elif domain.endswith('.ml'):
            return WhoisML(domain, text)
        elif domain.endswith('.za'):
            return WhoisZa(domain, text)
        elif domain.endswith('.bz'):
            return WhoisBz(domain, text)
        elif domain.endswith('.design'):
            return WhoisDesign(domain, text)
        elif domain.endswith('.style'):
            return WhoisStyle(domain, text)
        elif domain.endswith('.рус') or domain.endswith('.xn--p1acf'):
            return WhoisPyc(domain, text)
        elif domain.endswith('.ad'):
            return WhoisAero(domain, text)
        elif domain.endswith('.asia'):
            return WhoisAsia(domain, text)
        elif domain.endswith('.top'):
            return WhoisTop(domain, text)
        elif domain.endswith('.berlin'):
            return WhoisBerlin(domain, text)
        elif domain.endswith('.gl'):
            return WhoisGl(domain, text)
        elif domain.endswith('.lease'):
            return WhoisLease(domain, text)
        elif domain.endswith('.one'):
            return WhoisOne(domain, text)
        elif domain.endswith('.photo'):
            return WhoisPhoto(domain, text)
        elif domain.endswith('amsterdam'):
            return WhoisAmsterdam(domain, text)
        elif domain.endswith('.ac'):
            return WhoisAc(domain, text)
        elif domain.endswith('.mk'):
            return WhoisMk(domain, text)
        elif domain.endswith('.ag'):
            return WhoisAg(domain, text)
        elif domain.endswith('.cd'):
            return WhoisCd(domain, text)
        elif domain.endswith('.ci'):
            return WhoisCi(domain, text)
        elif domain.endswith('.co'):
            return WhoisCo(domain, text)
        elif domain.endswith('.cx'):
            return WhoisCx(domain, text)
        elif domain.endswith('.dm'):
            return WhoisDm(domain, text)
        elif domain.endswith('.fo'):
            return WhoisFo(domain, text)
        elif domain.endswith('.gd'):
            return WhoisGd(domain, text)
        elif domain.endswith('.ge'):
            return WhoisGe(domain, text)
        elif domain.endswith('.gq'):
            return WhoisGq(domain, text)
        elif domain.endswith('.gs'):
            return WhoisGs(domain, text)
        elif domain.endswith('.gy'):
            return WhoisGy(domain, text)
        elif domain.endswith('.ht'):
            return WhoisHt(domain, text)
        elif domain.endswith('.ke'):
            return WhoisKe(domain, text)
        elif domain.endswith('.kn'):
            return WhoisKn(domain, text)
        elif domain.endswith('.ky'):
            return WhoisKy(domain, text)
        elif domain.endswith('.la'):
            return WhoisLa(domain, text)
        elif domain.endswith('.lc'):
            return WhoisLc(domain, text)
        elif domain.endswith('.ly'):
            return WhoisLy(domain, text)
        elif domain.endswith('.ma'):
            return WhoisMa(domain, text)
        elif domain.endswith('.md'):
            return WhoisMd(domain, text)
        elif domain.endswith('.mg'):
            return WhoisMg(domain, text)
        elif domain.endswith('.mn'):
            return WhoisMn(domain, text)
        elif domain.endswith('.ms'):
            return WhoisMs(domain, text)
        elif domain.endswith('.mu'):
            return WhoisMu(domain, text)
        elif domain.endswith('.nc'):
            return WhoisNc(domain, text)
        elif domain.endswith('.nf'):
            return WhoisNf(domain, text)
        elif domain.endswith('.ng'):
            return WhoisNg(domain, text)
        elif domain.endswith('.om'):
            return WhoisOm(domain, text)
        elif domain.endswith('.paris'):
            return WhoisParis(domain, text)
        elif domain.endswith('.ps'):
            return WhoisPs(domain, text)
        elif domain.endswith('.pk'):
            return WhoisPk(domain, text)
        elif domain.endswith('.fashion'):
            return WhoisFashion(domain, text)
        elif domain.endswith('.melbourne'):
            return WhoisMelbourne(domain, text)
        elif domain.endswith('.wales'):
            return WhoisWales(domain, text)
        elif domain.endswith('.re'):
            return WhoisRe(domain, text)
        elif domain.endswith('.ug'):
            return WhoisUg(domain, text)
        elif domain.endswith('.ws'):
            return WhoisWs(domain, text)
        else:
            logger.warning(f'No specific TLD parser for domain {domain}. Using generic parser.')
            return WhoisEntry(domain, text)


class WhoisUg(WhoisEntry):
    """Whois parser for .ug domains"""

    regex = {
        'domain_name': r'Domain name: *(.+)',
        'registrant_name': r'Registrant name: *(.+)',
        'registrant_organization': r'Registrant organization: *(.+)',
        'creation_date': r'Registered On: *(.+)',
        'expiration_date': r'Expires On: *(.+)',
        'updated_date': r'Renewed On: *(.+)',
        'name_servers': r'Nameserver: *(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCc(WhoisEntry):
    """Whois parser for .cc domains"""

    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'name_servers': r'Nameserver: *(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'No match for' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSn(WhoisEntry):
    """Whois parser for .sn domains"""

    regex = {
        'domain_name': r'Nom de domaine: *(.+)',
        'creation_date': r'Date de création: *(.+)',
        'expiration_date': r'Date d\'expiration: *(.+)',
        'updated_date': r'Dernière modification: *(.+)',
        'registrar': r'Registrar: *(.+)',
    }

    def __init__(self, domain, text):
        if 'NOT FOUND' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCl(WhoisEntry):
    """Whois parser for .cl domains"""

    regex = {
        'domain_name': r'Domain name: *(.+)',
        'registrant_name': r'Registrant name: *(.+)',
        'registrant_organization': r'Registrant organisation: *(.+)',
        'registrar': r'registrar name: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'creation_date': r'Creation date: *(.+)',
        'expiration_date': r'Expiration date: *(.+)',
        'name_servers': r'Name server: *(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'no entries found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSo(WhoisEntry):
    """Whois parser for .so domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):

        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMk(WhoisEntry):
    """Whois parser for .mk domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'creation_date': r'registered: *(.+)',
        'updated_date': r'changed: *(.+)',
        'expiration_date': r'expire: *(.+)',
        'emails': EMAIL_REGEX,
    }
    dayfirst = True

    def __init__(self, domain, text):

        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisFj(WhoisEntry):
    """Whois parser for .fj domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):

        if 'No Object Found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMo(WhoisEntry):
    """Whois parser for .mo domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'creation_date': r'Record created on *(.+)',
        'expiration_date': r'Record expires on *(.+)',
    }

    def __init__(self, domain, text):
        if 'No match for' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisVe(WhoisEntry):
    """Whois parser for .ve domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'updated_date': r'changed: *(.+)',
        'creation_date': r'registered: *(.+)',
        'expiration_date': r'expire: *(.+)',
        'name_servers': r'nserver: *(.+)',
    }

    dayfirst = True

    def __init__(self, domain, text):
        if text.strip() == 'El dominio no existe.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSg(WhoisEntry):
    """Whois parser for .sg domains"""

    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrant_name': r'Registrant:\n\s+Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Expiration Date: *(.+)',
        'update_date': r'Modified Date: *(.+)',
    }

    def __init__(self, domain, text):

        if 'Domain Not Found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

        nsmatch = re.compile('Name Servers:(.*?)DNSSEC:', re.DOTALL).search(text)
        if nsmatch:
            self['name_servers'] = [line.strip() for line in nsmatch.groups()[0].strip().splitlines()]

        techmatch = re.compile('Technical Contact:(.*?)Name Servers:', re.DOTALL).search(text)
        if techmatch:
            for line in techmatch.groups()[0].strip().splitlines():
                self['technical_contact_' + line.split(':')[0].strip().lower()] = line.split(':')[1].strip()


class WhoisPe(WhoisEntry):
    """Whois parser for .pe domains"""

    regex = {
        'domain_name': r'Domain name: *(.+)',
        'status': r'Domain Status: *(.+)',
        'whois_server': r'WHOIS Server: *(.+)',
        'registrant_name': r'Registrant name: *(.+)',
        'registrar': r'Sponsoring Registrar: *(.+)',
        'admin': r'Admin Name: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'name_servers': r'Name server: *(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisQa(WhoisEntry):
    """Whois parser for .qa domains"""

    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'status': r'Status: *(.+)',
        'registrar': r'Registrar Name: *(.+)',
        'update_date': r'Last Modified: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'No Data Found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBn(WhoisEntry):
    """Whois parser for .bn domains"""

    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'update_date': r'Modified Date: *(.+)',
        'create_date': r'Creation Date: *(.+)',
        'expiration_date': r'Expiration Date: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Domain Not Found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisRe(WhoisEntry):
    """Whois parser for .re domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'creation_date': r'created: *(.+)',
        'update_date': r'Expiry Date: *(.+)',
        'expiration_date': r'last-update: *(.+)',
        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):

        if 'NOT FOUND' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMw(WhoisEntry):
    """Whois parser for .mw domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'creation_date': r'registered: *(.+)',
        'updated_date': r'changed: *(.+)',
        'expiration_date': r'expire: *(.+)',
        'emails': EMAIL_REGEX,
    }
    dayfirst = True

    def __init__(self, domain, text):

        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPf(WhoisEntry):
    """Whois parser for .pf domains"""
    regex = {
        'domain_name': r'Informations about \'(.+)\' :',
        'registrar': r'Registrar Company Name : (.+)',
        'creation_date': r'Created \(JJ/MM/AAAA\) : (.+)',
        'update_date': r'Last renewed \(JJ/MM/AAAA\) : (.+)',
        'expiration_date': r'Expire \(JJ/MM/AAAA\) : (.+)',
        'emails': EMAIL_REGEX,
    }
    dayfirst = True

    def __init__(self, domain, text):

        if 'Domain unknown' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisHu(WhoisEntry):
    """Whois parser for .hu domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'creation_date': r'record created: *(.+)',
        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):

        if 'Nincs talalat / No match' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisTz(WhoisEntry):
    """Whois parser for .tz domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'creation_date': r'registered: *(.+)',
        'updated_date': r'changed: *(.+)',
        'expiration_date': r'expire: *(.+)',
        'emails': EMAIL_REGEX,
    }
    dayfirst = True

    def __init__(self, domain, text):

        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCom(WhoisEntry):
    """Whois parser for .com domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisNet(WhoisEntry):
    """Whois parser for .net domains"""

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisOrg(WhoisEntry):
    """Whois parser for .org domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'whois_server': r'Whois Server: *(.+)',  # empty usually
        'referral_url': r'Referral URL: *(.+)',  # http url of whois_server: empty usually
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'status': r'Status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
    }

    def __init__(self, domain, text):
        if 'Domain not found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text)


class WhoisEdu(WhoisEntry):
    """Whois parser for .edu domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'organisation: *(.+)',
        'registrant_function': WhoisEntry.parse_indented_registrant,
        'whois_server': r'whois: *(.+)',  # empty usually
        'referral_url': r'refer: *(.+)',  # http url of whois_server: empty usually
        'updated_date': r'Domain record last updated: *(.+)',
        'creation_date': r'Domain record activated: *(.+)',
        'expiration_date': r'Domain expires: *(.+)',
        'name_servers': WhoisEntry.parse_indented_nameservers,  # list of name servers
        'status': r'status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
    }

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisGov(WhoisEntry):
    """Whois parser for .gov domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'organisation: *(.+)',
        'whois_server': r'whois: *(.+)',  # empty usually
        'referral_url': r'refer: *(.+)',  # http url of whois_server: empty usually
        'updated_date': r'changed: *(.+)',
        'creation_date': r'created: *(.+)',
        'name_servers': r'nserver: *(.+)',  # list of name servers
        'status': r'status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
    }

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisRo(WhoisEntry):
    """Whois parser for .ro domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'domain_status': r'Domain Status: *(.+)',
        'registrar': r'Registrar: *(.+)',

        'referral_url': r'Referral URL: *(.+)',  # http url of whois_server: empty usually

        'creation_date': r'Registered On: *(.+)',
        'expiration_date': r'Expires On: *(.+)',
        'name_servers': r'Nameserver: *(.+)',  # list of name servers
        'status': r'Status: *(.+)',  # list of statuses
        'dnssec': r'DNSSEC: *(.+)',
        'emails': EMAIL_REGEX  # list of email addresses
    }

    def __init__(self, domain, text):
        if text.strip() == 'NOT FOUND':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPk(WhoisEntry):
    """Whois parser for .pk domains"""
    regex = {
        'domain_name': r'Domain: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Expiry Date: *(.+)',
        'name_servers': r'Name Server: *(.+) \|',  # list of name servers
        'emails': EMAIL_REGEX,  # list of email addresses
    }

    def __init__(self, domain, text):
        if 'Status: Not Registered' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisTh(WhoisEntry):
    """Whois parser for .th domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar:(.+)',
        'name_servers': r'Name Server: *(.+)',
        'creation_date': r'Created date: *(.+)',
        'expiration_date': r'Exp date: *(.+)',
        'updated_date': r'Updated Date: (.+)',
        'status': r'Status: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No information available about domain name' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisRs(WhoisEntry):
    """Whois parser for .rs domains"""
    regex = {
        'domain_name': r'Domain name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'creation_date': r'Registration date: *(.+)',
        'expiration_date': r'Expiration date: *(.+)',
        'updated_date': r'Modification date: *(.+)',
        'emails': EMAIL_REGEX,  # list of email addresses
    }

    dayfirst = True

    def __init__(self, domain, text):
        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisRu(WhoisEntry):
    """Whois parser for .ru domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'creation_date': r'created: *(.+)',
        'expiration_date': r'paid-till: *(.+)',
        'updated_date': None,
        'name_servers': r'nserver: *(.+)',  # list of name servers
        'status': r'state: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
        'org': r'org: *(.+)'
    }

    def __init__(self, domain, text):
        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNl(WhoisEntry):
    """Whois parser for .nl domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'expiration_date': r'Date\sout\sof\squarantine:\s*(.+)',
        'updated_date': r'Updated\sDate:\s*(.+)',
        'creation_date': r'Creation\sDate:\s*(.+)',
        'status': r'Status: *(.+)',  # list of statuses
        'name': None,
        'registrar': r'Registrar:\s*(.*\n)',
        'registrar_address': r'Registrar:\s*(?:.*\n){1}\s*(.*)',
        'registrar_postal_code': r'Registrar:\s*(?:.*\n){2}\s*(\S*)\s(?:.*)',
        'registrar_city': r'Registrar:\s*(?:.*\n){2}\s*(?:\S*)\s(.*)',
        'registrar_country': r'Registrar:\s*(?:.*\n){3}\s*(.*)',
        'dnssec': r'DNSSEC: *(.+)',
        'emails': EMAIL_REGEX  # list of email addresses
    }

    def __init__(self, domain, text):
        if text.endswith('is free') or 'Server too busy, try again later' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

        match = re.compile(r'Domain nameservers:(.*?)Record maintained by', re.DOTALL).search(text)
        if match:
            duplicate_nameservers_with_ip = [line.strip()
                                             for line in match.groups()[0].strip().splitlines()]
            duplicate_nameservers_without_ip = [nameserver.split(' ')[0]
                                                for nameserver in duplicate_nameservers_with_ip]
            self['name_servers'] = sorted(list(set(duplicate_nameservers_without_ip)))


class WhoisLt(WhoisEntry):
    """Whois parser for .lt domains"""
    regex = {
        'domain_name': r'Domain:\s?(.+)',
        'expiration_date': r'Expires:\s?(.+)',
        'creation_date': r'Registered:\s?(.+)',
        'status': r'\nStatus:\s?(.+)',  # list of statuses
        'name': None,
        'emails': EMAIL_REGEX  # list of email addresses
    }

    def __init__(self, domain, text):
        if text.endswith('available'):
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

        match = re.compile(r'Domain nameservers:(.*?)Record maintained by', re.DOTALL).search(text)
        if match:
            duplicate_nameservers_with_ip = [line.strip()
                                             for line in match.groups()[0].strip().splitlines()]
            duplicate_nameservers_without_ip = [nameserver.split(' ')[0]
                                                for nameserver in duplicate_nameservers_with_ip]
            self['name_servers'] = sorted(list(set(duplicate_nameservers_without_ip)))


class WhoisAsGgJe(WhoisEntry):
    """Whois parser for .as .gg .je domains
    """
    regex = {
        'domain_name': r'Domain:[\r\n ]+(.+)',
        'creation_date': r'Relevant dates:[\r\n ]+ Registered on(.+)',
        'registrar': r'Registrar:[\r\n ]+(.+)',
    }

    def __init__(self, domain, text):
        if 'NOT FOUND' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisName(WhoisEntry):
    """Whois parser for .name domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'creation_date': r'Created On: *(.+)',
        'expiration_date': r'Expires On: *(.+)',
        'updated_date': r'Updated On: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'status': r'Domain Status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX  # list of email addresses
    }

    def __init__(self, domain, text):
        if 'No match for ' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisUs(WhoisEntry):
    """Whois parser for .us domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Domain ID: *(.+)',
        'whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_id': r'Registrar IANA ID: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'registrar_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',  # list of statuses
        'registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_organization': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state_province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_application_purpose': r'Registrant Application Purpose: *(.+)',
        'registrant_nexus_category': r'Registrant Nexus Category: *(.+)',
        'admin_id': r'Registry Admin ID: *(.+)',
        'admin': r'Admin Name: *(.+)',
        'admin_organization': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state_province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_application_purpose': r'Admin Application Purpose: *(.+)',
        'admin_nexus_category': r'Admin Nexus Category: *(.+)',
        'tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_organization': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state_province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_application_purpose': r'Tech Application Purpose: *(.+)',
        'tech_nexus_category': r'Tech Nexus Category: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPl(WhoisEntry):
    """Whois parser for .pl domains"""
    regex = {
        'domain_name': r'DOMAIN NAME: *(.+)\n',
        'name_servers': r'nameservers:((?:\s+.+\n+)*)',
        'registrar': r'REGISTRAR:\s*(.+)',
        'registrar_url': r'URL: *(.+)',  # not available
        'status': r'Registration status:\n\s*(.+)',  # not available
        'registrant_name': r'Registrant:\n\s*(.+)',  # not available
        'creation_date': r'(?<! )created: *(.+)\n',
        'expiration_date': r'renewal date: *(.+)',
        'updated_date': r'last modified: *(.+)\n',
    }

    def __init__(self, domain, text):
        if 'No information available about domain name' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCa(WhoisEntry):
    """Whois parser for .ca domains"""
    regex = {
        'domain_name': r'Domain name: *(.+)',
        'whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_number': r'Registry Registrant ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'status': r'Domain status: *(.+)',
        'emails': r'Email: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Expiry Date: *(.+)',
        'phone': r'Phone: *(.+)',
        'fax': r'Fax: *(.+)',
        'dnssec': r'dnssec: *([\S]+)',
        'name_servers': r'Name Server: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Domain status:         available' in text or 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMe(WhoisEntry):
    """Whois parser for .me domains"""
    regex = {
        'registry_domain_id': r'Registry Domain ID:(.+)',
        'domain_name': r'Domain Name:(.+)',
        'creation_date': r'Creation Date:(.+)',
        'updated_date': r'Updated Date:(.+)',
        'expiration_date': r'Registry Expiry Date: (.+)',
        'registrar': r'Registrar:(.+)',
        'status': r'Domain Status:(.+)',  # list of statuses
        'registrant_id': r'Registrant ID:(.+)',
        'registrant_name': r'Registrant Name:(.+)',
        'registrant_org': r'Registrant Organization:(.+)',
        'registrant_address': r'Registrant Address:(.+)',
        'registrant_address2': r'Registrant Address2:(.+)',
        'registrant_address3': r'Registrant Address3:(.+)',
        'registrant_city': r'Registrant City:(.+)',
        'registrant_state_province': r'Registrant State/Province:(.+)',
        'registrant_country': r'Registrant Country/Economy:(.+)',
        'registrant_postal_code': r'Registrant Postal Code:(.+)',
        'registrant_phone': r'Registrant Phone:(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext\.:(.+)',
        'registrant_fax': r'Registrant FAX:(.+)',
        'registrant_fax_ext': r'Registrant FAX Ext\.:(.+)',
        'registrant_email': r'Registrant E-mail:(.+)',
        'admin_id': r'Admin ID:(.+)',
        'admin_name': r'Admin Name:(.+)',
        'admin_org': r'Admin Organization:(.+)',
        'admin_address': r'Admin Address:(.+)',
        'admin_address2': r'Admin Address2:(.+)',
        'admin_address3': r'Admin Address3:(.+)',
        'admin_city': r'Admin City:(.+)',
        'admin_state_province': r'Admin State/Province:(.+)',
        'admin_country': r'Admin Country/Economy:(.+)',
        'admin_postal_code': r'Admin Postal Code:(.+)',
        'admin_phone': r'Admin Phone:(.+)',
        'admin_phone_ext': r'Admin Phone Ext\.:(.+)',
        'admin_fax': r'Admin FAX:(.+)',
        'admin_fax_ext': r'Admin FAX Ext\.:(.+)',
        'admin_email': r'Admin E-mail:(.+)',
        'tech_id': r'Tech ID:(.+)',
        'tech_name': r'Tech Name:(.+)',
        'tech_org': r'Tech Organization:(.+)',
        'tech_address': r'Tech Address:(.+)',
        'tech_address2': r'Tech Address2:(.+)',
        'tech_address3': r'Tech Address3:(.+)',
        'tech_city': r'Tech City:(.+)',
        'tech_state_province': r'Tech State/Province:(.+)',
        'tech_country': r'Tech Country/Economy:(.+)',
        'tech_postal_code': r'Tech Postal Code:(.+)',
        'tech_phone': r'Tech Phone:(.+)',
        'tech_phone_ext': r'Tech Phone Ext\.:(.+)',
        'tech_fax': r'Tech FAX:(.+)',
        'tech_fax_ext': r'Tech FAX Ext\.:(.+)',
        'tech_email': r'Tech E-mail:(.+)',
        'name_servers': r'Nameservers:(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'NOT FOUND' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisUk(WhoisEntry):
    """Whois parser for .uk domains"""
    regex = {
        'domain_name': r'Domain name:\s*(.+)',

        'registrar': r'Registrar:\s*(.+)',
        'registrar_url': r'URL:\s*(.+)',

        'status': r'Registration status:\s*(.+)',  # list of statuses

        'registrant_name': r'Registrant:\s*(.+)',
        'registrant_type': r'Registrant type:\s*(.+)',
        'registrant_street': r'Registrant\'s address:\s*(?:.*\n){2}\s+(.*)',
        'registrant_city': r'Registrant\'s address:\s*(?:.*\n){3}\s+(.*)',
        'registrant_country': r'Registrant\'s address:\s*(?:.*\n){5}\s+(.*)',

        'creation_date': r'Registered on:\s*(.+)',
        'expiration_date': r'Expiry date:\s*(.+)',
        'updated_date': r'Last updated:\s*(.+)',

        'name_servers': WhoisEntry.parse_indented_nameservers,
    }

    def __init__(self, domain, text):
        if 'No match for ' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisFr(WhoisEntry):
    """Whois parser for .fr domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'name': r'holder-c: *(.+)',
        'creation_date': r'created: *(.+)',
        'expiration_date': r'Expir\w+ Date:\s?(.+)',
        'name_servers': r'nserver: *(.+)',  # list of name servers
        'status': r'status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
        'updated_date': r'last-update: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisFi(WhoisEntry):
    """Whois parser for .fi domains"""
    regex = {
        'domain_name': r'domain\.*: *([\S]+)',
        'name': r'Holder\s*name\.*: (.+)',
        'address': r'[Holder\w\W]address\.*: (.+)',
        'phone': r'Holder[\s\w\W]+phone\.*: (.+)',
        'email': r'holder email\.*: *([\S]+)',
        'status': r'status\.*: (.+)',  # list of statuses
        'creation_date': r'created\.*: *([\S]+)',
        'updated_date': r'modified\.*: *([\S]+)',
        'expiration_date': r'expires\.*: *([\S]+)',
        'name_servers': r'nserver\.*: *([\S]+) \[\S+\]',  # list of name servers
        'name_server_statuses': r'nserver\.*: *([\S]+ \[\S+\])',  # list of name servers and statuses
        'dnssec': r'dnssec\.*: *([\S]+)',
        'registrar': r'Registrar\s*registrar\.*: (.+)',
        'registrar_site': r'Registrar[\s\w\W]+www\.*: (.+)'

    }

    dayfirst = True

    def __init__(self, domain, text):
        if 'Domain not ' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisJp(WhoisEntry):
    """Whois parser for .jp domains"""
    regex = {
        'domain_name': r'\[Domain Name\] *(.+)|a. \[ドメイン名]\ *(.+)',
        'creation_date': r'\[登録年月日\] *(.+)',
        'name_servers': r'p\. \[ネームサーバ\] *(.+)',  # list of name servers
        'updated_date': r'\[最終更新\] *(.+)|\[接続年月日\] *(.+)',
        'expiration_date': r'\[有効期限\] *(.+)',
        'status': r'\[状態\] *(.+)',  # list of statuses
        'emails': EMAIL_REGEX  # list of email addresses
    }

    def __init__(self, domain, text):
        if 'No match!!' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAM(WhoisEntry):
    """Whois parser for .am domains"""
    regex = {
        'creation_date': r'Registered: *(.+)',
        'updated_date': r'Last modified: *(.+)',
        'expiration_date': r'Expires: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'No Data Found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAU(WhoisEntry):
    """Whois parser for .au domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)\n',
        'updated_date': r'Last Modified: *(.+)\n',
        'registrar': r'Registrar Name: *(.+)\n',
        'status': r'Status: *(.+)',
        'registrant_name': r'Registrant: *(.+)',
        'registrant_contact_name': r'Registrant Contact Name: (.+)',
        'name_servers': r'Name Server: *(.+)',
        'emails': EMAIL_REGEX  # list of email addresses
    }

    def __init__(self, domain, text):
        if text.strip() == 'No Data Found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisEu(WhoisEntry):
    """Whois parser for .eu domains"""
    regex = {
        'domain_name': r'Domain: *([^\n\r]+)',
        'tech_name': r'Technical: *Name: *([^\n\r]+)',
        'tech_org': r'Technical: *Name: *[^\n\r]+\s*Organisation: *([^\n\r]+)',
        'tech_phone': r'Technical: *Name: *[^\n\r]+\s*Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *(['
                      r'^\n\r]+)',
        'tech_fax': r'Technical: *Name: *[^\n\r]+\s*Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *['
                    r'^\n\r]+\s*Fax: *([^\n\r]+)',
        'tech_email': r'Technical: *Name: *[^\n\r]+\s*Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *['
                      r'^\n\r]+\s*Fax: *[^\n\r]+\s*Email: *([^\n\r]+)',
        'registrar': r'Registrar:\n *Name: *([^\n\r]+)',
        'registrar_url': r'\n *Website: *([^\n\r]+)',
        'name_servers': r'Name servers:\n *([\n\S\s]+)',  # list of name servers
        'emails': EMAIL_REGEX  # list of email addresses
    }

    def __init__(self, domain, text):
        if text.strip() == 'Status: AVAILABLE':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisEe(WhoisEntry):
    """Whois parser for .ee domains"""
    regex = {
        'domain_name': r'Domain: *[\n\r]+\s*name: *([^\n\r]+)',
        'status': r'Domain: *[\n\r]+\s*name: *[^\n\r]+\sstatus: *([^\n\r]+)',
        'creation_date': r'Domain: *[\n\r]+\s*name: *[^\n\r]+\sstatus: *[^\n\r]+\sregistered: *([^\n\r]+)',
        'updated_date': r'Domain: *[\n\r]+\s*name: *[^\n\r]+\sstatus: *[^\n\r]+\sregistered: *[^\n\r]+\schanged: '
                        r'*([^\n\r]+)',
        'expiration_date': r'Domain: *[\n\r]+\s*name: *[^\n\r]+\sstatus: *[^\n\r]+\sregistered: *[^\n\r]+\schanged: '
                           r'*[^\n\r]+\sexpire: *([^\n\r]+)',

        # 'tech_name': r'Technical: *Name: *([^\n\r]+)',
        # 'tech_org': r'Technical: *Name: *[^\n\r]+\s*Organisation: *([^\n\r]+)',
        # 'tech_phone': r'Technical: *Name: *[^\n\r]+\s*
        # Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *([^\n\r]+)',
        # 'tech_fax': r'Technical: *Name: *[^\n\r]+\s*
        # Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *[^\n\r]+\s*Fax: *([^\n\r]+)',
        # 'tech_email': r'Technical: *Name: *[^\n\r]+\s*
        # Organisation: *[^\n\r]+\s*Language: *[^\n\r]+\s*Phone: *[^\n\r]+\s*Fax: *[^\n\r]+\s*Email: *([^\n\r]+)',
        'registrar': r'Registrar: *[\n\r]+\s*name: *([^\n\r]+)',
        'name_servers': r'nserver: *(.*)',  # list of name servers
        'emails': EMAIL_REGEX  # list of email addresses
    }

    def __init__(self, domain, text):
        if text.strip() == 'Domain not found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBr(WhoisEntry):
    """Whois parser for .br domains"""
    regex = {
        'domain_name': r'domain: *(.+)\n',
        'registrant_name': r'owner: *([\S ]+)',
        'registrant_id': r'ownerid: *(.+)',
        'country': r'country: *(.+)',
        'owner_c': r'owner-c: *(.+)',
        'admin_c': r'admin-c: *(.+)',
        'tech_c': r'tech-c: *(.+)',
        'billing_c': r'billing-c: *(.+)',
        'name_servers': r'nserver: *(.+)',
        'nsstat': r'nsstat: *(.+)',
        'nslastaa': r'nslastaa: *(.+)',
        'saci': r'saci: *(.+)',
        'creation_date': r'created: *(.+)',
        'updated_date': r'changed: *(.+)',
        'expiration_date': r'expires: *(.+)',
        'status': r'status: *(.+)',
        'nic_hdl_br': r'nic-hdl-br: *(.+)',
        'person': r'person: *([\S ]+)',
        'email': EMAIL_REGEX,
    }

    def __init__(self, domain, text):

        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

    def _preprocess(self, attr, value):
        value = value.strip()
        if value and isinstance(value, basestring) and '_date' in attr:
            # try casting to date format
            value = re.findall(r"[\w\s:.-\\/]+", value)[0].strip()
            value = cast_date(
                value,
                dayfirst=self.dayfirst,
                yearfirst=self.yearfirst)
        return value


class WhoisKr(WhoisEntry):
    """Whois parser for .kr domains"""

    regex = {
        'domain_name': r'Domain Name\s*: *(.+)',
        'registrant_name': r'Registrant\s*: *(.+)',
        'registrant_address': r'Registrant Address\s*: *(.+)',
        'registrant_postal_code': r'Registrant Zip Code\s*: *(.+)',
        'admin_name': r'Administrative Contact\(AC\)\s*: *(.+)',
        'admin_email': r'AC E-Mail\s*: *(.+)',
        'admin_phone': r'AC Phone Number\s*: *(.+)',
        'creation_date': r'Registered Date\s*: *(.+)',
        'updated_date': r'Last updated Date\s*: *(.+)',
        'expiration_date': r'Expiration Date\s*: *(.+)',
        'registrar': r'Authorized Agency\s*: *(.+)',
        'name_servers': r'Host Name\s*: *(.+)',  # list of name servers
        'emails': EMAIL_REGEX  # list of email addresses
    }

    def __init__(self, domain, text):
        if text.endswith(' no match'):
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPt(WhoisEntry):
    """Whois parser for .pt domains"""
    regex = {
        'domain_name': r'Domain: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Expiration Date: *(.+)',
        'registrant_name': r'Owner Name: *(.+)',
        'registrant_street': r'Owner Address: *(.+)',
        'registrant_city': r'Owner Locality: *(.+)',
        'registrant_postal_code': r'Owner ZipCode: *(.+)',
        'registrant_email': r'Owner Email: *(.+)',
        'admin': r'Admin Name: *(.+)',
        'admin_street': r'Admin Address: *(.+)',
        'admin_city': r'Admin Locality: *(.+)',
        'admin_postal_code': r'Admin ZipCode: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'name_servers': r'Name Server: *(.+) \|',  # list of name servers
        'status': r'Domain Status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
    }
    dayfirst = True

    def __init__(self, domain, text):
        if text.strip() == 'No entries found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBg(WhoisEntry):
    """Whois parser for .bg domains"""
    regex = {
        'domain_name': r'DOMAIN NAME: *(.+)\n',
        'status': r'registration status: s*(.+)',
        'expiration_date': r'expires at: *(.+)',
        'emails': EMAIL_REGEX  # list of email addresses
    }
    dayfirst = True

    def __init__(self, domain, text):
        if 'registration status: available' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDe(WhoisEntry):
    """Whois parser for .de domains"""
    regex = {
        'domain_name': r'Domain: *(.+)',
        'status': r'Status: *(.+)',
        'updated_date': r'Changed: *(.+)',
        'name': r'name: *(.+)',
        'org': r'Organisation: *(.+)',
        'address': r'Address: *(.+)',
        'registrant_postal_code': r'PostalCode: *(.+)',
        'city': r'City: *(.+)',
        'country_code': r'CountryCode: *(.+)',
        'phone': r'Phone: *(.+)',
        'fax': r'Fax: *(.+)',
        'name_servers': r'Nserver: *(.+)',  # list of name servers
        'emails': EMAIL_REGEX  # list of email addresses

    }

    def __init__(self, domain, text):
        if 'Status: free' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAt(WhoisEntry):
    """Whois parser for .at domains"""
    regex = {
        'domain_name': r'domain:\s*(.+)',
        'registrar': r'registrar:\s*(.+)',
        'registrant_id': r'registrant:\s*(.+)',
        'tech_id': r'tech-c:\s*(.+)',
        'name_servers': r'nserver:\s*(.+)',  # list of name servers
        'updated_date': r'changed:\s*(.+)',

        'name': r'personname:\s*(.+)',
        'org': r'organization:\s*(.+)',
        'address': r'street address:\s*(.+)',
        'registrant_postal_code': r'postal code:\s*(.+)',
        'city': r'city:\s*(.+)',
        'country': r'country:\s*(.+)',
        'phone': r'phone:\s*(.+)',
        'email': EMAIL_REGEX,
        'fax': r'fax-no:\s*(.+)',
        'nic_hdl': r'nic-hdl:\s*(.+)',

    }

    def __init__(self, domain, text):
        if '% nothing found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

    def _preprocess(self, attr, value):
        value = super(WhoisAt, self)._preprocess(attr, value)
        if attr == 'registrar' and value and isinstance(value, basestring):
            f = re.search(r'^(.+)\s+\(\s*.+/(\d+)\s*\)', value)
            if f:
                value = f.group(1)
                self['registrar_nicat_id'] = f.group(2)
        return value

class WhoisBe(WhoisEntry):
    """Whois parser for .be domains"""
    regex = {
        'name': r'Domain:\s*(.+)',
        'creation_date': r'Registered:\s*(.+)',
        'registrar': r'Registrar:\s*[\s\t\n]+Name:\s*(.+)',
        'name_servers': r'Nameservers:\n([\sa-z0-9\-\.]+)\n\n',  # list of name servers
        'status': r'Flags:\n([\sa-z0-9\-\.]+)\n\n',  # list of flags
    }

    def __init__(self, domain, text):
        if 'Status: AVAILABLE' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text.replace('\r', ''), self.regex)

    def _preprocess(self, attr, value):
        value = super(WhoisBe, self)._preprocess(attr, value)
        if attr in ('name_servers', 'status') and value:
            res = set()
            for val in value.strip().split('\n'):
                res.add(val.strip())
            return list(res)
        return value

class WhoisInfo(WhoisEntry):
    """Whois parser for .info domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'whois_server': r'Registrar Whois Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Domain not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisRf(WhoisRu):
    """Whois parser for .rf domains"""

    def __init__(self, domain, text):
        WhoisRu.__init__(self, domain, text)


class WhoisSu(WhoisRu):
    """Whois parser for .su domains"""

    def __init__(self, domain, text):
        WhoisRu.__init__(self, domain, text)


class WhoisBz(WhoisRu):
    """Whois parser for .bz domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_id': r'Registrar IANA ID: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',

        'status': r'Domain Status: *(.+)',  # list of statuses

        'registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_organization': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state_province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone_number': r'(?:Registrant Phone|Registrar Abuse Contact Phone): *(.+)',
        'registrant_phone_number_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_email': r'(?:Registrant Email|Registrar Abuse Contact Email): *(.+)',

        'admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_organization': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state_province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_country_code': r'Administrative Contact Country Code: *(.+)',
        'admin_phone_number': r'Admin Phone: *(.+)',
        'admin_phone_number_ext': r'Admin Phone Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',

        'tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_organization': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state_province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone_number': r'Tech Phone: *(.+)',
        'tech_phone_number_ext': r'Tech Phone Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',

        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registrar Registration Expiration Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDesign(WhoisEntry):
    """Whois parser for .design domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisStyle(WhoisRu):
    """Whois parser for .style domains"""

    def __init__(self, domain, text):
        WhoisRu.__init__(self, domain, text)


class WhoisPyc(WhoisRu):
    """Whois parser for .рус domains"""

    def __init__(self, domain, text):
        WhoisRu.__init__(self, domain, text)


class WhoisClub(WhoisEntry):
    """Whois parser for .club domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Domain ID: *(.+)',
        'registrar': r'Sponsoring Registrar: *(.+)',
        'registrar_id': r'Sponsoring Registrar IANA ID: *(.+)',
        'registrar_url': r'Registrar URL \(registration services\): *(.+)',
        # list of statuses
        'status': r'Domain Status: *(.+)',
        'registrant_id': r'Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_address1': r'Registrant Address1: *(.+)',
        'registrant_address2': r'Registrant Address2: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state_province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_country_code': r'Registrant Country Code: *(.+)',
        'registrant_phone_number': r'Registrant Phone Number: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registrant_application_purpose': r'Registrant Application Purpose: *(.+)',
        'registrant_nexus_category': r'Registrant Nexus Category: *(.+)',
        'admin_id': r'Administrative Contact ID: *(.+)',
        'admin_name': r'Administrative Contact Name: *(.+)',
        'admin_address1': r'Administrative Contact Address1: *(.+)',
        'admin_address2': r'Administrative Contact Address2: *(.+)',
        'admin_city': r'Administrative Contact City: *(.+)',
        'admin_state_province': r'Administrative Contact State/Province: *(.+)',
        'admin_postal_code': r'Administrative Contact Postal Code: *(.+)',
        'admin_country': r'Administrative Contact Country: *(.+)',
        'admin_country_code': r'Administrative Contact Country Code: *(.+)',
        'admin_phone_number': r'Administrative Contact Phone Number: *(.+)',
        'admin_email': r'Administrative Contact Email: *(.+)',
        'admin_application_purpose': r'Administrative Application Purpose: *(.+)',
        'admin_nexus_category': r'Administrative Nexus Category: *(.+)',
        'billing_id': r'Billing Contact ID: *(.+)',
        'billing_name': r'Billing Contact Name: *(.+)',
        'billing_address1': r'Billing Contact Address1: *(.+)',
        'billing_address2': r'Billing Contact Address2: *(.+)',
        'billing_city': r'Billing Contact City: *(.+)',
        'billing_state_province': r'Billing Contact State/Province: *(.+)',
        'billing_postal_code': r'Billing Contact Postal Code: *(.+)',
        'billing_country': r'Billing Contact Country: *(.+)',
        'billing_country_code': r'Billing Contact Country Code: *(.+)',
        'billing_phone_number': r'Billing Contact Phone Number: *(.+)',
        'billing_email': r'Billing Contact Email: *(.+)',
        'billing_application_purpose': r'Billing Application Purpose: *(.+)',
        'billing_nexus_category': r'Billing Nexus Category: *(.+)',
        'tech_id': r'Technical Contact ID: *(.+)',
        'tech_name': r'Technical Contact Name: *(.+)',
        'tech_address1': r'Technical Contact Address1: *(.+)',
        'tech_address2': r'Technical Contact Address2: *(.+)',
        'tech_city': r'Technical Contact City: *(.+)',
        'tech_state_province': r'Technical Contact State/Province: *(.+)',
        'tech_postal_code': r'Technical Contact Postal Code: *(.+)',
        'tech_country': r'Technical Contact Country: *(.+)',
        'tech_country_code': r'Technical Contact Country Code: *(.+)',
        'tech_phone_number': r'Technical Contact Phone Number: *(.+)',
        'tech_email': r'Technical Contact Email: *(.+)',
        'tech_application_purpose': r'Technical Application Purpose: *(.+)',
        'tech_nexus_category': r'Technical Nexus Category: *(.+)',
        # list of name servers
        'name_servers': r'Name Server: *(.+)',
        'created_by_registrar': r'Created by Registrar: *(.+)',
        'last_updated_by_registrar': r'Last Updated by Registrar: *(.+)',
        'creation_date': r'Domain Registration Date: *(.+)',
        'expiration_date': r'Domain Expiration Date: *(.+)',
        'updated_date': r'Domain Last Updated Date: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIo(WhoisEntry):
    """Whois parser for .io domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_id': r'Registrar IANA ID: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registrant_name': r'Registrant Organization: *(.+)',
        'registrant_state_province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Domain not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBiz(WhoisEntry):
    """Whois parser for .biz domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Domain ID: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'registrar_id': r'Registrar IANA ID: *(.+)',
        'registrar_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',  # list of statuses
        'registrant_id': r'Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_address': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state_province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_country_code': r'Registrant Country Code: *(.+)',
        'registrant_phone_number': r'Registrant Phone: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_organization': r'Admin Organization: *(.+)',
        'admin_address': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state_province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone_number': r'Admin Phone: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_organization': r'Tech Organization: *(.+)',
        'tech_address': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state_province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone_number': r'Tech Phone: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registrar Registration Expiration Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No Data Found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMobi(WhoisEntry):
    """Whois parser for .mobi domains"""
    regex = {
        'registry_domain_id': r'Registry Domain ID:(.+)',
        'domain_name': r'Domain Name:(.+)',
        'creation_date': r'Creation Date:(.+)',
        'updated_date': r'Updated Date:(.+)',
        'expiration_date': r'Registry Expiry Date: (.+)',
        'registrar': r'Registrar:(.+)',
        'status': r'Domain Status:(.+)',  # list of statuses
        'registrant_id': r'Registrant ID:(.+)',
        'registrant_name': r'Registrant Name:(.+)',
        'registrant_org': r'Registrant Organization:(.+)',
        'registrant_address': r'Registrant Address:(.+)',
        'registrant_address2': r'Registrant Address2:(.+)',
        'registrant_address3': r'Registrant Address3:(.+)',
        'registrant_city': r'Registrant City:(.+)',
        'registrant_state_province': r'Registrant State/Province:(.+)',
        'registrant_country': r'Registrant Country/Economy:(.+)',
        'registrant_postal_code': r'Registrant Postal Code:(.+)',
        'registrant_phone': r'Registrant Phone:(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext\.:(.+)',
        'registrant_fax': r'Registrant FAX:(.+)',
        'registrant_fax_ext': r'Registrant FAX Ext\.:(.+)',
        'registrant_email': r'Registrant E-mail:(.+)',
        'admin_id': r'Admin ID:(.+)',
        'admin_name': r'Admin Name:(.+)',
        'admin_org': r'Admin Organization:(.+)',
        'admin_address': r'Admin Address:(.+)',
        'admin_address2': r'Admin Address2:(.+)',
        'admin_address3': r'Admin Address3:(.+)',
        'admin_city': r'Admin City:(.+)',
        'admin_state_province': r'Admin State/Province:(.+)',
        'admin_country': r'Admin Country/Economy:(.+)',
        'admin_postal_code': r'Admin Postal Code:(.+)',
        'admin_phone': r'Admin Phone:(.+)',
        'admin_phone_ext': r'Admin Phone Ext\.:(.+)',
        'admin_fax': r'Admin FAX:(.+)',
        'admin_fax_ext': r'Admin FAX Ext\.:(.+)',
        'admin_email': r'Admin E-mail:(.+)',
        'tech_id': r'Tech ID:(.+)',
        'tech_name': r'Tech Name:(.+)',
        'tech_org': r'Tech Organization:(.+)',
        'tech_address': r'Tech Address:(.+)',
        'tech_address2': r'Tech Address2:(.+)',
        'tech_address3': r'Tech Address3:(.+)',
        'tech_city': r'Tech City:(.+)',
        'tech_state_province': r'Tech State/Province:(.+)',
        'tech_country': r'Tech Country/Economy:(.+)',
        'tech_postal_code': r'Tech Postal Code:(.+)',
        'tech_phone': r'Tech Phone:(.+)',
        'tech_phone_ext': r'Tech Phone Ext\.:(.+)',
        'tech_fax': r'Tech FAX:(.+)',
        'tech_fax_ext': r'Tech FAX Ext\.:(.+)',
        'tech_email': r'Tech E-mail:(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'Domain not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisKg(WhoisEntry):
    """Whois parser for .kg domains"""
    regex = {
        'domain_name': r'Domain\s*([\w]+\.[\w]{2,5})',
        'registrar': r'Domain support: \s*(.+)',
        'registrant_name': r'Name: *(.+)',
        'registrant_address': r'Address: *(.+)',
        'registrant_phone_number': r'phone: *(.+)',
        'registrant_email': r'Email: *(.+)',
        # # list of name servers
        'name_servers': r'Name servers in the listed order: *([\d\w\.\s]+)',
        # 'name_servers':                 r'([\w]+\.[\w]+\.[\w]{2,5}\s*\d{1,3}\.\d]{1,3}\.[\d]{1-3}\.[\d]{1-3})',
        'creation_date': r'Record created: *(.+)',
        'expiration_date': r'Record expires on: *(.+)',
        'updated_date': r'Record last updated on: *(.+)',

    }

    def __init__(self, domain, text):
        if 'Data not found. This domain is available for registration' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisChLi(WhoisEntry):
    """Whois Parser for .ch and .li domains"""
    regex = {
        'domain_name': r'\nDomain name:\n*(.+)',
        'registrant_name': r'Holder of domain name:\s*(?:.*\n){1}\s*(.+)',
        'registrant_address': r'Holder of domain name:\s*(?:.*\n){2}\s*(.+)',
        'registrar': r'Registrar:\n*(.+)',
        'creation_date': r'First registration date:\n*(.+)',
        'dnssec': r'DNSSEC:*([\S]+)',
        'tech-c': r'Technical contact:\n*([\n\s\S]+)\nRegistrar:',
        'name_servers': r'Name servers:\n *([\n\S\s]+)'
    }

    def __init__(self, domain, text):
        if 'We do not have an entry in our database matching your query.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisID(WhoisEntry):
    """Whois parser for .id domains"""
    regex = {
        'registry_domain_id': r'Domain ID:(.+)',
        'domain_name': r'Domain Name:(.+)',
        'creation_date': r'Created On:(.+)',
        'expiration_date': r'Expiration Date:(.+)',
        'updated_date': r'Last Updated On:(.+)',
        'dnssec': r'DNSSEC:(.+)',

        'registrar': r'Sponsoring Registrar Organization:(.+)',
        'registrar_city': r'Sponsoring Registrar City:(.+)',
        'registrar_postal_code': r'Sponsoring Registrar Postal Code:(.+)',
        'registrar_country': r'Sponsoring Registrar Country:(.+)',
        'registrar_phone': r'Sponsoring Registrar Phone:(.+)',
        'registrar_email': r'Sponsoring Registrar Contact Email:(.+)',

        'status': r'Status:(.+)',  # list of statuses

        'registrant_id': r'Registrant ID:(.+)',
        'registrant_name': r'Registrant Name:(.+)',
        'registrant_org': r'Registrant Organization:(.+)',
        'registrant_address': r'Registrant Street1:(.+)',
        'registrant_address2': r'Registrant Street2:(.+)',
        'registrant_address3': r'Registrant Street3:(.+)',
        'registrant_city': r'Registrant City:(.+)',
        'registrant_country': r'Registrant Country:(.+)',
        'registrant_postal_code': r'Registrant Postal Code:(.+)',
        'registrant_phone': r'Registrant Phone:(.+)',
        'registrant_fax': r'Registrant FAX:(.+)',
        'registrant_email': r'Registrant Email:(.+)',

        'name_servers': r'Name Server:(.+)',  # list of name servers
    }

    def __init__(self, domain, text):
        if 'NOT FOUND' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSe(WhoisEntry):
    """Whois parser for .se domains"""
    regex = {
        'domain_name': r'domain\.*: *(.+)',
        'registrant_name': r'holder\.*: *(.+)',
        'creation_date': r'created\.*: *(.+)',
        'updated_date': r'modified\.*: *(.+)',
        'expiration_date': r'expires\.*: *(.+)',
        'transfer_date': r'transferred\.*: *(.+)',
        'name_servers': r'nserver\.*: *(.+)',  # list of name servers
        'dnssec': r'dnssec\.*: *(.+)',
        'status': r'status\.*: *(.+)',  # list of statuses
        'registrar': r'registrar: *(.+)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisJobs(WhoisEntry):
    """Whois parser for .jobs domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'status': r'Domain Status: *(.+)',
        'whois_server': r'Registrar WHOIS Server: *(.+)',

        'registrar_url': r'Registrar URL: *(.+)',
        'registrar_name': r'Registrar: *(.+)',
        'registrar_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_phone': r'Registrar Abuse Contact Phone: *(.+)',

        'registrant_name': r'Registrant Name: (.+)',
        'registrant_id': r'Registry Registrant ID: (.+)',
        'registrant_organization': r'Registrant Organization: (.+)',
        'registrant_city': r'Registrant City: (.*)',
        'registrant_street': r'Registrant Street: (.*)',
        'registrant_state_province': r'Registrant State/Province: (.*)',
        'registrant_postal_code': r'Registrant Postal Code: (.*)',
        'registrant_country': r'Registrant Country: (.+)',
        'registrant_phone': r'Registrant Phone: (.+)',
        'registrant_fax': r'Registrant Fax: (.+)',
        'registrant_email': r'Registrant Email: (.+)',

        'admin_name': r'Admin Name: (.+)',
        'admin_id': r'Registry Admin ID: (.+)',
        'admin_organization': r'Admin Organization: (.+)',
        'admin_city': r'Admin City: (.*)',
        'admin_street': r'Admin Street: (.*)',
        'admin_state_province': r'Admin State/Province: (.*)',
        'admin_postal_code': r'Admin Postal Code: (.*)',
        'admin_country': r'Admin Country: (.+)',
        'admin_phone': r'Admin Phone: (.+)',
        'admin_fax': r'Admin Fax: (.+)',
        'admin_email': r'Admin Email: (.+)',

        'billing_name': r'Billing Name: (.+)',
        'billing_id': r'Registry Billing ID: (.+)',
        'billing_organization': r'Billing Organization: (.+)',
        'billing_city': r'Billing City: (.*)',
        'billing_street': r'Billing Street: (.*)',
        'billing_state_province': r'Billing State/Province: (.*)',
        'billing_postal_code': r'Billing Postal Code: (.*)',
        'billing_country': r'Billing Country: (.+)',
        'billing_phone': r'Billing Phone: (.+)',
        'billing_fax': r'Billing Fax: (.+)',
        'billing_email': r'Billing Email: (.+)',

        'tech_name': r'Tech Name: (.+)',
        'tech_id': r'Registry Tech ID: (.+)',
        'tech_organization': r'Tech Organization: (.+)',
        'tech_city': r'Tech City: (.*)',
        'tech_street': r'Tech Street: (.*)',
        'tech_state_province': r'Tech State/Province: (.*)',
        'tech_postal_code': r'Tech Postal Code: (.*)',
        'tech_country': r'Tech Country: (.+)',
        'tech_phone': r'Tech Phone: (.+)',
        'tech_fax': r'Tech Fax: (.+)',
        'tech_email': r'Tech Email: (.+)',

        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'name_servers': r'Name Server: *(.+)'

    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIt(WhoisEntry):
    """Whois parser for .it domains"""
    regex = {
        'domain_name': r'Domain: *(.+)',
        'creation_date': r'(?<! )Created: *(.+)',
        'updated_date': r'(?<! )Last Update: *(.+)',
        'expiration_date': r'(?<! )Expire Date: *(.+)',
        'status': r'Status: *(.+)',  # list of statuses
        'name_servers': r'Nameservers[\s]((?:.+\n)*)',  # servers in one string sep by \n

        'registrant_organization': r'(?<=Registrant)[\s\S]*?Organization:(.*)',
        'registrant_address': r'(?<=Registrant)[\s\S]*?Address:(.*)',

        'admin_address': r'(?<=Admin Contact)[\s\S]*?Address:(.*)',
        'admin_organization': r'(?<=Admin Contact)[\s\S]*?Organization:(.*)',
        'admin_name': r'(?<=Admin Contact)[\s\S]*?Name:(.*)',

        'tech_address': r'(?<=Technical Contacts)[\s\S]*?Address:(.*)',
        'tech_organization': r'(?<=Technical Contacts)[\s\S]*?Organization:(.*)',
        'tech_name': r'(?<=Technical Contacts)[\s\S]*?Name:(.*)',

        'registrar_address': r'(?<=Registrar)[\s\S]*?Address:(.*)',
        'registrar': r'(?<=Registrar)[\s\S]*?Organization:(.*)',
        'registrar_name': r'(?<=Registrar)[\s\S]*?Name:(.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSa(WhoisEntry):
    """Whois parser for .sa domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'creation_date': r'Created on: *(.+)',
        'updated_date': r'Last Updated on: *(.+)',
        'name_servers': r'Name Servers:[\s]((?:.+\n)*)',  # servers in one string sep by \n

        'registrant_name': r'Registrant:\s*(.+)',
        'registrant_address': r'(?<=Registrant)[\s\S]*?Address:((?:.+\n)*)',

        'admin_address': r'(?<=Administrative Contact)[\s\S]*?Address:((?:.+\n)*)',
        'admin': r'Administrative Contact:\s*(.*)',

        'tech_address': r'(?<=Technical Contact)[\s\S]*?Address:((?:.+\n)*)',
        'tech': r'Technical Contact:\s*(.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSK(WhoisEntry):
    """Whois parser for .sk domains"""
    regex = {
        'domain_name': r'Domain: *(.+)',
        'creation_date': r'(?<=Domain:)[\s\w\W]*?Created: *(.+)',
        'updated_date': r'(?<=Domain:)[\s\w\W]*?Updated: *(.+)',
        'expiration_date': r'Valid Until: *(.+)',
        'name_servers': r'Nameserver: *(.+)',

        'registrar': r'(?<=Registrar)[\s\S]*?Organization:(.*)',
        'registrar_organization_id': r'(?<=Registrar)[\s\S]*?Organization ID:(.*)',
        'registrar_name': r'(?<=Registrar)[\s\S]*?Name:(.*)',
        'registrar_phone': r'(?<=Registrar)[\s\S]*?Phone:(.*)',
        'registrar_email': r'(?<=Registrar)[\s\S]*?Email:(.*)',
        'registrar_street': r'(?<=Registrar)[\s\S]*?Street:(.*)',
        'registrar_city': r'(?<=Registrar)[\s\S]*?City:(.*)',
        'registrar_postal_code': r'(?<=Registrar)[\s\S]*?Postal Code:(.*)',
        'registrar_country_code': r'(?<=Registrar)[\s\S]*?Country Code:(.*)',
        'registrar_created': r'(?<=Registrant)[\s\S]*?Created:(.*)',
        'registrar_updated': r'(?<=Registrant)[\s\S]*?Updated:(.*)',

        'admin': r'Contact:\s*(.*)',
        'admin_organization': r'(?<=Contact)[\s\S]*Organization:(.*)',
        'admin_email': r'(?<=Contact)[\s\S]*Email:(.*)',
        'admin_street': r'(?<=Contact)[\s\S]*Street:(.*)',
        'admin_city': r'(?<=Contact)[\s\S]*City:(.*)',
        'admin_postal_code': r'(?<=Contact)[\s\S]*Postal Code:(.*)',
        'admin_country_code': r'(?<=Contact)[\s\S]*Country Code:(.*)',

    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMx(WhoisEntry):
    """Whois parser for .mx domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'creation_date': r'Created On: *(.+)',
        'updated_date': r'Last Updated On: *(.+)',
        'expiration_date': r'Expiration Date: *(.+)',
        'url': r'URL: *(.+)',

        'name_servers': r'DNS: (.*)',  # servers in one string sep by \n

        'registrar': r'Registrar:\s*(.+)',

        'registrant_name': r'(?<=Registrant)[\s\S]*?Name:(.*)',
        'registrant_city': r'(?<=Registrant)[\s\S]*?City:(.*)',
        'registrant_state': r'(?<=Registrant)[\s\S]*?State:(.*)',
        'registrant_country': r'(?<=Registrant)[\s\S]*?Country:(.*)',

        'admin': r'(?<=Administrative Contact)[\s\S]*?Name:(.*)',
        'admin_city': r'(?<=Administrative Contact)[\s\S]*?City:(.*)',
        'admin_country': r'(?<=Administrative Contact)[\s\S]*?Country:(.*)',
        'admin_state': r'(?<=Administrative Contact)[\s\S]*?State:(.*)',

        'tech_name': r'(?<=Technical Contact)[\s\S]*?Name:(.*)',
        'tech_city': r'(?<=Technical Contact)[\s\S]*?City:(.*)',
        'tech_state': r'(?<=Technical Contact)[\s\S]*?State:(.*)',
        'tech_country': r'(?<=Technical Contact)[\s\S]*?Country:(.*)',

        'billing_name': r'(?<=Billing Contact)[\s\S]*?Name:(.*)',
        'billing_city': r'(?<=Billing Contact)[\s\S]*?City:(.*)',
        'billing_state': r'(?<=Billing Contact)[\s\S]*?State:(.*)',
        'billing_country': r'(?<=Billing Contact)[\s\S]*?Country:(.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisTw(WhoisEntry):
    """Whois parser for .tw domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'creation_date': r'Record created on (.+) ',
        'expiration_date': r'Record expires on (.+) ',

        # servers in one string sep by \n
        'name_servers': r'Domain servers in listed order:((?:\s.+)*)',

        'registrar': r'Registration Service Provider: *(.+)',
        'registrar_url': r'Registration Service URL: *(.+)',

        'registrant_name': r'(?<=Registrant:)\s+(.*)',
        'registrant_organization': r'(?<=Registrant:)\s*(.*)',
        'registrant_city': r'(?<=Registrant:)\s*(?:.*\n){5}\s+(.*),',
        'registrant_street': r'(?<=Registrant:)\s*(?:.*\n){4}\s+(.*)',
        'registrant_state_province': r'(?<=Registrant:)\s*(?:.*\n){5}.*, (.*)',
        'registrant_country': r'(?<=Registrant:)\s*(?:.*\n){6}\s+(.*)',
        'registrant_phone': r'(?<=Registrant:)\s*(?:.*\n){2}\s+(\+*\d.*)',
        'registrant_fax': r'(?<=Registrant:)\s*(?:.*\n){3}\s+(\+*\d.*)',
        'registrant_email': r'(?<=Registrant:)\s*(?:.*\n){1}.*  (.*)',

        'admin': r'(?<=Administrative Contact:\n)\s+(.*)  ',
        'admin_email': r'(?<=Administrative Contact:)\s*.*  (.*)',
        'admin_phone': r'(?<=Administrative Contact:\n)\s*(?:.*\n){1}\s+(\+*\d.*)',
        'admin_fax': r'(?<=Administrative Contact:\n)\s*(?:.*\n){2}\s+(\+*\d.*)',

        'tech': r'(?<=Technical Contact:\n)\s+(.*)  ',
        'tech_email': r'(?<=Technical Contact:)\s*.*  (.*)',
        'tech_phone': r'(?<=Technical Contact:\n)\s*(?:.*\n){1}\s+(\+*\d.*)',
        'tech_fax': r'(?<=Technical Contact:\n)\s*(?:.*\n){2}\s+(\+*\d.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisTr(WhoisEntry):
    """Whois parser for .tr domains"""
    regex = {
        'domain_name': r'[**] Domain Name: *(.+)',

        'creation_date': r'Created on.*: *(.+)',
        'expiration_date': r'Expires on.*: *(.+)',

        'name_servers': r'[**] Domain servers:((?:\s.+)*)',  # servers in one string sep by \n

        'registrant_name': r'(?<=[**] Registrant:)[\s\S]((?:\s.+)*)',

        'admin': r'(?<=[**] Administrative Contact:)[\s\S]*?NIC Handle\s+: (.*)',
        'admin_organization': r'(?<=[**] Administrative Contact:)[\s\S]*?Organization Name\s+: (.*)',
        'admin_address': r'(?<=[**] Administrative Contact)[\s\S]*?Address\s+: (.*)',
        'admin_phone': r'(?<=[**] Administrative Contact)[\s\S]*?Phone\s+: (.*)',
        'admin_fax': r'(?<=[**] Administrative Contact)[\s\S]*?Fax\s+: (.*)',

        'tech': r'(?<=[**] Technical Contact:)[\s\S]*?NIC Handle\s+: (.*)',
        'tech_organization': r'(?<=[**] Technical Contact:)[\s\S]*?Organization Name\s+: (.*)',
        'tech_address': r'(?<=[**] Technical Contact)[\s\S]*?Address\s+: (.*)',
        'tech_phone': r'(?<=[**] Technical Contact)[\s\S]*?Phone\s+: (.*)',
        'tech_fax': r'(?<=[**] Technical Contact)[\s\S]*?Fax\s+: (.*)',

        'billing': r'(?<=[**] Billing Contact:)[\s\S]*?NIC Handle\s+: (.*)',
        'billing_organization': r'(?<=[**] Billing Contact:)[\s\S]*?Organization Name\s+: (.*)',
        'billing_address': r'(?<=[**] Billing Contact)[\s\S]*?Address\s+: (.*)',
        'billing_phone': r'(?<=[**] Billing Contact)[\s\S]*?Phone\s+: (.*)',
        'billing_fax': r'(?<=[**] Billing Contact)[\s\S]*?Fax\s+: (.*)',
    }

    def __init__(self, domain, text):
        if 'not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIs(WhoisEntry):
    """Whois parser for .se domains"""
    regex = {
        'domain_name': r'domain\.*: *(.+)',
        'registrant_name': r'registrant: *(.+)',
        'name': r'person\.*: *(.+)',
        'address': r'address\.*: *(.+)',
        'creation_date': r'created\.*: *(.+)',
        'expiration_date': r'expires\.*: *(.+)',
        'email': r'e-mail: *(.+)',
        'name_servers': r'nserver\.*: *(.+)',  # list of name servers
        'dnssec': r'dnssec\.*: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDk(WhoisEntry):
    """Whois parser for .dk domains"""
    regex = {
        'domain_name': r'Domain: *(.+)',
        'creation_date': r'Registered: *(.+)',
        'expiration_date': r'Expires: *(.+)',
        'dnssec': r'Dnssec: *(.+)',
        'status': r'Status: *(.+)',
        'registrant_handle': r'Registrant\s*(?:.*\n){1}\s*Handle: *(.+)',
        'registrant_name': r'Registrant\s*(?:.*\n){2}\s*Name: *(.+)',
        'registrant_address': r'Registrant\s*(?:.*\n){3}\s*Address: *(.+)',
        'registrant_postal_code': r'Registrant\s*(?:.*\n){4}\s*Postalcode: *(.+)',
        'registrant_city': r'Registrant\s*(?:.*\n){5}\s*City: *(.+)',
        'registrant_country': r'Registrant\s*(?:.*\n){6}\s*Country: *(.+)',
        'name_servers': r'Nameservers\n *([\n\S\s]+)'
    }

    def __init__(self, domain, text):
        if 'No match for ' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

    def _preprocess(self, attr, value):
        if attr == 'name_servers':
            return [
                line.split(":")[-1].strip()
                for line in value.split("\n")
                if line.startswith("Hostname")
            ]
        return super(WhoisDk, self)._preprocess(attr, value)


class WhoisAi(WhoisEntry):
    """Whois parser for .ai domains"""
    regex = {
        'domain_name': r'Domain Name\.*: *(.+)',
        'registry_domain_id': r'Registry Domain ID\.*: *(.+)',
        'creation_date': r'Creation Date: (.+)',
        'registrar': r'Registrar: (.+)',
        'registrar_phone': r'Registrar Abuse Contact Phone:(.+)',
        'registrar_email': r'Registrar Abuse Contact Email:(.+)',
        'registrant_name': r'RegistrantName: *(.+)',
        'registrant_org': r'RegistrantOrganization: (.+)',
        'registrant_address': r'RegistrantStreet: *(.+)',
        'registrant_city': r'RegistrantCity: *(.+)',
        'registrant_state': r'RegistrantState.*: *(.+)',
        'registrant_postal_code': r'RegistrantPostal Code\.*: *(\d+)',
        'registrant_country': r'RegistrantCountry\.*: *(.+)',
        'registrant_phone': r'RegistrantPhone\.*: *(.+)',
        'registrant_email': r'RegistrantEmail\.*: *(.+)',
        'admin_name': r'AdminName: *(.+)',
        'admin_org': r'AdminOrganization: (.+)',
        'admin_address': r'AdminStreet: *(.+)',
        'admin_city': r'AdminCity: *(.+)',
        'admin_state': r'AdminState.*: *(.+)',
        'admin_postal_code': r'AdminPostal Code\.*: *(\d+)',
        'admin_country': r'AdminCountry\.*: *(.+)',
        'admin_phone': r'AdminPhone\.*: *(.+)',
        'admin_email': r'AdminEmail\.*: *(.+)',
        'tech_name': r'TechName: *(.+)',
        'tech_org': r'TechOrganization: (.+)',
        'tech_address': r'TechStreet: *(.+)',
        'tech_city': r'TechCity: *(.+)',
        'tech_state': r'TechState.*: *(.+)',
        'tech_postal_code': r'TechPostal Code\.*: *(\d+)',
        'tech_country': r'TechCountry\.*: *(.+)',
        'tech_phone': r'TechPhone\.*: *(.+)',
        'tech_email': r'TechEmail\.*: *(.+)',
        'billing_name': r'BillingName: *(.+)',
        'billing_org': r'BillingOrganization: (.+)',
        'billing_address': r'BillingStreet: *(.+)',
        'billing_city': r'BillingCity: *(.+)',
        'billing_state': r'BillingState.*: *(.+)',
        'billing_postal_code': r'BillingPostal Code\.*: *(\d+)',
        'billing_country': r'BillingCountry\.*: *(.+)',
        'billing_phone': r'BillingPhone\.*: *(.+)',
        'billing_email': r'BillingEmail\.*: *(.+)',
        'name_servers': r'Name Server\.*: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No Object Found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIl(WhoisEntry):
    """Whois parser for .il domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'expiration_date': r'validity: *(.+)',
        'registrant_name': r'person: *(.+)',
        'registrant_address': r'address *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'status': r'status: *(.+)',
        'name_servers': r'nserver: *(.+)',
        'emails': EMAIL_REGEX,
        'phone': r'phone: *(.+)',
        'registrar': r'registrar name: *(.+)',
        'referral_url': r'registrar info: *(.+)',
    }
    dayfirst = True

    def __init__(self, domain, text):
        if 'No data was found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIn(WhoisEntry):
    """Whois parser for .in domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'whois_server': r'Registrar Whois Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'NOT FOUND' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCat(WhoisEntry):
    """Whois parser for .cat domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'status': r'Domain status: *(.+)',
        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):
        if 'no matching objects' in text:
            raise PywhoisError(text)
        else:
            # Merge base class regex with specifics
            self._regex.copy().update(self.regex)
            self.regex = self._regex
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIe(WhoisEntry):
    """Whois parser for .ie domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'status': r'Domain status: *(.+)',
        'admin_id': r'Registry Admin ID: *(.+)',
        'tech_id': r'Registry Tech ID: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_contact': r'Registrar Abuse Contact Email: *(.+)',
        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):
        if 'no matching objects' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNz(WhoisEntry):
    """Whois parser for .nz domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'emails': EMAIL_REGEX,  # list of emails
    }

    def __init__(self, domain, text):
        if 'no matching objects' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisLu(WhoisEntry):
    """Whois parser for .lu domains"""
    regex = {
        'domain_name': r'domainname: *(.+)',
        'creation_date': r'registered: *(.+)',
        'name_servers': r'nserver: *(.+)',
        'status': r'domaintype: *(.+)',
        'registrar': r'registrar-name: *(.+)',
        'registrant_name': r'org-name: *(.+)',
        'registrant_address': r'org-address: *(.+)',
        'registrant_postal_code': r'org-zipcode:*(.+)',
        'registrant_city': r'org-city: *(.+)',
        'registrant_country': r'org-country: *(.+)',
        'admin_name': r'adm-name: *(.+)',
        'admin_address': r'adm-address: *(.+)',
        'admin_postal_code': r'adm-zipcode: *(.+)',
        'admin_city': r'adm-city: *(.+)',
        'admin_country': r'adm-country: *(.+)',
        'admin_email': r'adm-email: *(.+)',
        'tech_name': r'tec-name: *(.+)',
        'tech_address': r'tec-address: *(.+)',
        'tech_postal_code': r'tec-zipcode: *(.+)',
        'tech_city': r'tec-city: *(.+)',
        'tech_country': r'tec-country: *(.+)',
        'tech_email': r'tec-email: *(.+)',
        'emails': EMAIL_REGEX,
    }

    dayfirst = True

    def __init__(self, domain, text):
        if 'No such domain' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCz(WhoisEntry):
    """Whois parser for .cz domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrant_name': r'registrant: *(.+)',
        'registrar': r'registrar: *(.+)',
        'creation_date': r'registered: *(.+)',
        'updated_date': r'changed: *(.+)',
        'expiration_date': r'expire: *(.+)',
        'name_servers': r'nserver: *(.+)',
        'emails': EMAIL_REGEX,
    }

    dayfirst = True

    def __init__(self, domain, text):
        if '% No entries found.' in text or 'Your connection limit exceeded' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisHr(WhoisEntry):
    """Whois parser for .hr domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registrar Registration Expiration Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'registrant_name': r'Registrant Name:\s(.+)',
        'registrant_address': r'Reigstrant Street:\s*(.+)',
        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):
        if 'ERROR: No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisHk(WhoisEntry):
    """Whois parser for .hk domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'status': r'Domain Status: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'whois_server': r'Registrar WHOIS Server: *(.+)',

        'registrar_url': r'Registrar URL: *(.+)',
        'registrar': r'Registrar Name: *(.+)',
        'registrar_email': r'Registrar Contact Information: Email: *(.+)',

        'registrant_company_name': r'Registrant Contact Information:\s*Company English Name.*:(.+)',
        'registrant_address': r'(?<=Registrant Contact Information:)[\s\S]*?Address: (.*)',
        'registrant_country': r'[Registrant Contact Information\w\W]+Country: ([\S\ ]+)',
        'registrant_email': r'[Registrant Contact Information\w\W]+Email: ([\S\ ]+)',

        'admin_name': r'[Administrative Contact Information\w\W]+Given name: ([\S\ ]+)',
        'admin_family_name': r'[Administrative Contact Information\w\W]+Family name: ([\S\ ]+)',
        'admin_company_name': r'[Administrative Contact Information\w\W]+Company name: ([\S\ ]+)',
        'admin_address': r'(?<=Administrative Contact Information:)[\s\S]*?Address: (.*)',
        'admin_country': r'[Administrative Contact Information\w\W]+Country: ([\S\ ]+)',
        'admin_phone': r'[Administrative Contact Information\w\W]+Phone: ([\S\ ]+)',
        'admin_fax': r'[Administrative Contact Information\w\W]+Fax: ([\S\ ]+)',
        'admin_email': r'[Administrative Contact Information\w\W]+Email: ([\S\ ]+)',
        'admin_account_name': r'[Administrative Contact Information\w\W]+Account Name: ([\S\ ]+)',

        'tech_name': r'[Technical Contact Information\w\W]+Given name: (.+)',
        'tech_family_name': r'[Technical Contact Information\w\W]+Family name: (.+)',
        'tech_company_name': r'[Technical Contact Information\w\W]+Company name: (.+)',
        'tech_address': r'(?<=Technical Contact Information:)[\s\S]*?Address: (.*)',
        'tech_country': r'[Technical Contact Information\w\W]+Country: (.+)',
        'tech_phone': r'[Technical Contact Information\w\W]+Phone: (.+)',
        'tech_fax': r'[Technical Contact Information\w\W]+Fax: (.+)',
        'tech_email': r'[Technical Contact Information\w\W]+Email: (.+)',
        'tech_account_name': r'[Technical Contact Information\w\W]+Account Name: (.+)',

        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'[Registrant Contact Information\w\W]+Domain Name Commencement Date: (.+)',
        'expiration_date': r'[Registrant Contact Information\w\W]+Expiry Date: (.+)',
        'name_servers': r'Name Servers Information:\s+((?:.+\n)*)',
        'emails': EMAIL_REGEX,
    }
    dayfirst = True

    def __init__(self, domain, text):
        if 'ERROR: No entries found' in text or 'The domain has not been registered' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisUA(WhoisEntry):
    """Whois parser for .ua domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'status': r'status: *(.+)',

        'registrar': r'(?<=Registrar:)[\s\W\w]*?organization-loc:(.*)',
        'registrar_name': r'(?<=Registrar:)[\s\W\w]*?registrar:(.*)',
        'registrar_url': r'(?<=Registrar:)[\s\W\w]*?url:(.*)',
        'registrar_country': r'(?<=Registrar:)[\s\W\w]*?country:(.*)',
        'registrar_city': r'(?<=Registrar:)[\s\W\w]*?city:\s+(.*)\n',
        'registrar_address': r'(?<=Registrar:)[\s\W\w]*?abuse-postal:\s+(.*)\n',
        'registrar_email': r'(?<=Registrar:)[\s\W\w]*?abuse-email:(.*)',

        'registrant_name': r'(?<=Registrant:)[\s\W\w]*?organization-loc:(.*)',
        'registrant_country': r'(?<=Registrant:)[\s\W\w]*?country-loc:(.*)',
        'registrant_city': r'(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){2}address-loc:\s+(.*)\n',
        'registrant_state': r'(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){1}address-loc:\s+(.*)\n',
        'registrant_address': r'(?<=Registrant:)[\s\W\w]*?address-loc:\s+(.*)\n',
        'registrant_email': r'(?<=Registrant:)[\s\W\w]*?e-mail:(.*)',
        'registrant_postal_code': r'(?<=Registrant:)[\s\W\w]*?postal-code-loc:(.*)',
        'registrant_phone': r'(?<=Registrant:)[\s\W\w]*?phone:(.*)',
        'registrant_fax': r'(?<=Registrant:)[\s\W\w]*?fax:(.*)',

        'admin': r'(?<=Administrative Contacts:)[\s\W\w]*?organization-loc:(.*)',
        'admin_country': r'(?<=Administrative Contacts:)[\s\W\w]*?country-loc:(.*)',
        'admin_city': r'(?<=Administrative Contacts:)[\s\W\w]*?(?:address\-loc:\s+.*\n){'
                      r'2}address-loc:\s+(.*)\n',
        'admin_state': r'(?<=Administrative Contacts:)[\s\W\w]*?(?:address\-loc:\s+.*\n){'
                       r'1}address-loc:\s+(.*)\n',
        'admin_address': r'(?<=Administrative Contacts:)[\s\W\w]*?address-loc:\s+(.*)\n',
        'admin_email': r'(?<=Administrative Contacts:)[\s\W\w]*?e-mail:(.*)',
        'admin_postal_code': r'(?<=Administrative Contacts:)[\s\W\w]*?postal-code-loc:(.*)',
        'admin_phone': r'(?<=Administrative Contacts:)[\s\W\w]*?phone:(.*)',
        'admin_fax': r'(?<=Administrative Contacts:)[\s\W\w]*?fax:(.*)',

        'updated_date': r'modified: *(.+)',
        'creation_date': r'created: (.+)',
        'expiration_date': r'expires: (.+)',
        'name_servers': r'nserver: *(.+)',

        'emails': EMAIL_REGEX,  # list of email addresses

    }

    def __init__(self, domain, text):
        if 'ERROR: No entries found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisUkr(WhoisEntry):
    """Whois parser for .укр domains"""
    regex = {
        'domain_name': r'Domain name \(UTF8\): *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'status': r'Registry Status: *(.+)',

        'registrar': r'Registrar: *(.+)',
        'registrar_id': r'Registrar ID: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'registrar_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_phone': r'Registrar Abuse Contact Phone: *(.+)',

        'registrant_name': r'Registrant Name \(Organization\): *(.+)',
        'registrant_address': r'Registrant Street:(.+)',
        'registrant_city': r'Registrant City:(.+)',
        'registrant_country': r'Registrant Country:(.+)',
        'registrant_postal_code': r'Registrant Postal Code:(.+)',
        'registrant_phone': r'Registrant Phone:(.+)',
        'registrant_fax': r'Registrant Fax:(.+)',
        'registrant_email': r'Registrant Email:(.+)',

        'admin': r'Admin Name: *(.+)',
        'admin_organization': r'Admin Organization: *(.+)',
        'admin_address': r'Admin Street:(.+)',
        'admin_city': r'Admin City:(.+)',
        'admin_country': r'Admin Country:(.+)',
        'admin_postal_code': r'Admin Postal Code:(.+)',
        'admin_phone': r'Admin Phone:(.+)',
        'admin_fax': r'Admin Fax:(.+)',
        'admin_email': r'Admin Email:(.+)',

        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: (.+)',
        'expiration_date': r'Expiration Date: (.+)',
        'name_servers': r'Domain servers in listed order:\s+((?:.+\n)*)',

        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):
        if 'No match for domain' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

    def _preprocess(self, attr, value):
        if attr == 'name_servers':
            return [
                line.strip()
                for line in value.split("\n")
                if line != ""
            ]
        return super(WhoisUkr, self)._preprocess(attr, value)


class WhoisPpUa(WhoisEntry):
    """Whois parser for .pp.ua domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Domain ID: *(.+)',
        'status': r'status: *(.+)',

        'registrar': r'Sponsoring Registrar: *(.+)',

        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_organization': r'Registrant Organization: *(.+)',
        'registrant_address': r'Registrant Street1:(.+)',
        'registrant_address2': r'Registrant Street2:(.+)',
        'registrant_address3': r'Registrant Street3:(.+)',
        'registrant_city': r'Registrant City:(.+)',
        'registrant_country': r'Registrant Country:(.+)',
        'registrant_postal_code': r'Registrant Postal Code:(.+)',
        'registrant_phone': r'Registrant Phone:(.+)',
        'registrant_fax': r'Registrant Fax:(.+)',
        'registrant_email': r'Registrant Email:(.+)',

        'admin': r'Admin Name: *(.+)',
        'admin_organization': r'Admin Organization: *(.+)',
        'admin_address': r'Admin Street1:(.+)',
        'admin_address2': r'Admin Street2:(.+)',
        'admin_address3': r'Admin Street3:(.+)',
        'admin_city': r'Admin City:(.+)',
        'admin_country': r'Admin Country:(.+)',
        'admin_postal_code': r'Admin Postal Code:(.+)',
        'admin_phone': r'Admin Phone:(.+)',
        'admin_fax': r'Admin Fax:(.+)',
        'admin_email': r'Admin Email:(.+)',

        'updated_date': r'Last Updated On: *(.+)',
        'creation_date': r'Created On: (.+)',
        'expiration_date': r'Expiration Date: (.+)',
        'name_servers': r'Name Server: *(.+)',

        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):
        if 'No entries found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisHn(WhoisEntry):
    """Whois parser for .hn domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Domain ID: *(.+)',
        'status': r'Domain Status: *(.+)',
        'whois_server': r'WHOIS Server: *(.+)',

        'registrar_url': r'Registrar URL: *(.+)',
        'registrar': r'Registrar: *(.+)',

        'registrant_name': r'Registrant Name: (.+)',
        'registrant_id': r'Registrant ID: (.+)',
        'registrant_organization': r'Registrant Organization: (.+)',
        'registrant_city': r'Registrant City: (.*)',
        'registrant_street': r'Registrant Street: (.*)',
        'registrant_state_province': r'Registrant State/Province: (.*)',
        'registrant_postal_code': r'Registrant Postal Code: (.*)',
        'registrant_country': r'Registrant Country: (.+)',
        'registrant_phone': r'Registrant Phone: (.+)',
        'registrant_fax': r'Registrant Fax: (.+)',
        'registrant_email': r'Registrant Email: (.+)',

        'admin_name': r'Admin Name: (.+)',
        'admin_id': r'Admin ID: (.+)',
        'admin_organization': r'Admin Organization: (.+)',
        'admin_city': r'Admin City: (.*)',
        'admin_street': r'Admin Street: (.*)',
        'admin_state_province': r'Admin State/Province: (.*)',
        'admin_postal_code': r'Admin Postal Code: (.*)',
        'admin_country': r'Admin Country: (.+)',
        'admin_phone': r'Admin Phone: (.+)',
        'admin_fax': r'Admin Fax: (.+)',
        'admin_email': r'Admin Email: (.+)',

        'billing_name': r'Billing Name: (.+)',
        'billing_id': r'Billing ID: (.+)',
        'billing_organization': r'Billing Organization: (.+)',
        'billing_city': r'Billing City: (.*)',
        'billing_street': r'Billing Street: (.*)',
        'billing_state_province': r'Billing State/Province: (.*)',
        'billing_postal_code': r'Billing Postal Code: (.*)',
        'billing_country': r'Billing Country: (.+)',
        'billing_phone': r'Billing Phone: (.+)',
        'billing_fax': r'Billing Fax: (.+)',
        'billing_email': r'Billing Email: (.+)',

        'tech_name': r'Tech Name: (.+)',
        'tech_id': r'Tech ID: (.+)',
        'tech_organization': r'Tech Organization: (.+)',
        'tech_city': r'Tech City: (.*)',
        'tech_street': r'Tech Street: (.*)',
        'tech_state_province': r'Tech State/Province: (.*)',
        'tech_postal_code': r'Tech Postal Code: (.*)',
        'tech_country': r'Tech Country: (.+)',
        'tech_phone': r'Tech Phone: (.+)',
        'tech_fax': r'Tech Fax: (.+)',
        'tech_email': r'Tech Email: (.+)',

        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',

        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):
        if text.strip() == 'No matching record.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCn(WhoisEntry):
    """Whois parser for .cn domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'creation_date': r'Registration Time: *(.+)',
        'expiration_date': r'Expiration Time: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'status': r'Status: *(.+)',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email s
        'dnssec': r'dnssec: *([\S]+)',
        'name': r'Registrant: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'No matching record.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisTn(WhoisEntry):
    """Whois parser for .tn domains"""
    regex = {
        'domain_name': r'Domain name.........: *(.+)',
        'registrar': r'Registrar...........: *(.+)',
        'creation_date': r'Creation date.......: *(.+)',
        'name_servers': r'Name................: *(.+)\.',  # list of name servers
        'emails': EMAIL_REGEX,  # list of emails
    }

    dayfirst = True

    def __init__(self, domain, text):
        if 'NO OBJECT FOUND!' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAr(WhoisEntry):
    """Whois parser for .ar domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'whois_server': r'whois: *(.+)',
        'updated_date': r'changed: *(.+)',
        'creation_date': r'registered: *(.+)',
        'expiration_date': r'expire: *(.+)',
        'name_servers': r'nserver: *(.+) \(.*\)',  # list of name servers
        'status': r'Domain Status: *(.+)',
        'emails': EMAIL_REGEX,  # list of emails
        'name': r'name: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'El dominio no se encuentra registrado en NIC Argentina':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBy(WhoisEntry):
    """Whois parser for .by domains"""
    regex = {
        'domain_name': r'Domain name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'updated_date': r'Update Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Expiration Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'status': r'Domain Status: *(.+)',  # could not be found in sample, but might be correct
        'name': r'Person: *(.+)',  # could not be found in sample, but might be correct
        'org': r'Org: *(.+)',
        'registration_id': r'Registration or other identification number: *(.+)',
        'registrant_country': r'Country: *(.+)',
        'registrant_address': r'Address: *(.+)',
        'registrant_phone': r'Phone: *(.+)',
        'registrant_email': r'Email: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'Object does not exist':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCr(WhoisEntry):
    """Whois parser for .cr domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrant_name': r'registrant: *(.+)',
        'registrar': r'registrar: *(.+)',
        'updated_date': r'changed: *(.+)',
        'creation_date': r'registered: *(.+)',
        'expiration_date': r'expire: *(.+)',
        'name_servers': r'nserver: *(.+)',  # list of name servers
        'status': r'status: *(.+)',
        'contact': r'contact: *(.+)',
        'name': r'name: *(.+)',
        'org': r'org: *(.+)',
        'address': r'address: *(.+)',
        'phone': r'phone: *(.+)',
    }

    dayfirst = True

    def __init__(self, domain, text):
        if text.strip() == 'El dominio no existe.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisVe(WhoisEntry):
    """Whois parser for .ve domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'updated_date': r'changed: *(.+)',
        'creation_date': r'registered: *(.+)',
        'expiration_date': r'expire: *(.+)',
        'name_servers': r'nserver: *(.+)',
    }

    dayfirst = True

    def __init__(self, domain, text):
        if text.strip() == 'El dominio no existe.':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDo(WhoisEntry):
    """Whois parser for .do domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'whois_server': r'WHOIS Server: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_email': r'Registrar Customer Service Email: *(.+)',
        'registrar_phone': r'Registrar Phone: *(.+)',
        'registrar_address': r'Registrar Address: *(.+)',
        'registrar_country': r'Registrar Country: *(.+)',
        'status': r'Domain Status: *(.+)',  # list of statuses
        'registrant_id': r'Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_organization': r'Registrant Organization: *(.+)',
        'registrant_address': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state_province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone_number': r'Registrant Phone: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'admin_id': r'Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_organization': r'Admin Organization: *(.+)',
        'admin_address': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state_province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone_number': r'Admin Phone: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'billing_id': r'Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_address': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state_province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone_number': r'Billing Phone: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'tech_id': r'Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_organization': r'Tech Organization: *(.+)',
        'tech_address': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state_province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone_number': r'Tech Phone: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'dnssec': r'DNSSEC: *(.+)'
    }

    def __init__(self, domain, text):
        if 'No Object Found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAe(WhoisEntry):
    """Whois parser for .ae domains"""
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'status': r'Status: *(.+)',
        'registrant_name': r'Registrant Contact Name: *(.+)',
        'tech_name': r'Tech Contact Name: *(.+)',
        'registrar': r'Registrar Name: *(.+)',
    }

    def __init__(self, domain, text):
        if text.strip() == 'No Data Found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisSi(WhoisEntry):
    """Whois parser for .si domains"""
    regex = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'name_servers': r'nameserver: *(.+)',
        'registrant_name': r'registrant: *(.+)',
        'creation_date': r'created: *(.+)',
        'expiration_date': r'expire: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No entries found for the selected source(s).' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNo(WhoisEntry):
    """Whois parser for .no domains"""
    regex = {
        'domain_name': r'Domain Name\.*:\s*(.+)',
        'registry_domain_id': r'NORID Handle\.*:\s*(.+)',
        'registrar_id': r'Registrar Handle\.*:\s*(.+)',
        'tech_id': r'Tech-c Handle\.*:\s*(.+)',
        'nameserver_handle': r'Name Server Handle\.*:\s*(.+)',
        'creation_date': r'Additional information:\nCreated:\s*(.+)',
        'updated_date': r'Additional information:\n(?:.*\n)Last updated:\s*(.+)',
    }

    def __init__(self, domain, text):
        if 'No match' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisKZ(WhoisEntry):
    """Whois parser for .kz domains"""
    regex = {
        'domain_name': r'Domain Name............: *(.+)',
        'registrar_created': r'Registrar Created: *(.+)',
        'current_registrar': r'Current Registrar: *(.+)',
        'creation_date': r'Domain created: *(.+)',
        'updated_date': r'Last modified : *(.+)',
        'name_servers': r'server.*: *(.+)',  # list of name servers
        'status': r' (.+?) -',  # list of statuses
        'emails': EMAIL_REGEX,  # list of email addresses
        'org': r'Organization Name.*: *(.+)'
    }

    def __init__(self, domain, text):
        if text.strip() == 'No entries found':
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIR(WhoisEntry):
    """Whois parser for .ir domains"""

    regex = {
        'domain_name': r'domain: *(.+)',
        'registrant_name': r'person: *(.+)',
        'registrant_organization': r'org: *(.+)',
        'updated_date': r'last-updated: *(.+)',
        'expiration_date': r'expire-date: *(.+)',
        'name_servers': r'nserver: *(.+)',  # list of name servers
        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisZhongGuo(WhoisEntry):
    """Whois parser for .中国 domains"""

    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'creation_date': r'Registration Time: *(.+)',
        'registrant_name': r'Registrant: *(.+)',
        'registrar': r'Sponsoring Registrar: *(.+)',
        'expiration_date': r'Expiration Time: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'emails': EMAIL_REGEX,
    }

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisML(WhoisEntry):
    """Whois parser for .ml domains"""

    regex = {
        'domain_name': r'Domain name:\s*([^(i|\n)]+)',
        'registrar': r'Organization: *(.+)',
        'creation_date': r'Domain registered: *(.+)',
        'expiration_date': r'Record will expire on: *(.+)',
        'name_servers': r'Domain Nameservers:\s+((?:.+\n)*)',
        'emails': EMAIL_REGEX
    }

    def __init__(self, domain, text):
        if 'Invalid query or domain name not known in the Point ML Domain Registry' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

    def _preprocess(self, attr, value):
        if attr == 'name_servers':
            return [
                line.strip()
                for line in value.split("\n")
                if line != ""
            ]
        return super(WhoisML, self)._preprocess(attr, value)


class WhoisZa(WhoisEntry):
    """Whois parser for .za domains"""

    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Domain ID: *(.+)',
        'whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_id': r'Registrar IANA ID: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'registrar_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_organization': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state_province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'admin_id': r'Registry Admin ID: *(.+)',
        'admin': r'Admin Name: *(.+)',
        'admin_organization': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state_province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_application_purpose': r'Admin Application Purpose: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_organization': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state_province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_phone_ext': r'Billing Phone Ext: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_fax_ext': r'Billing Fax Ext: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_organization': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state_province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'name_servers': r'Name Server: *(.+)',  # list of name servers
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
    }

    def __init__(self, domain, text):
        if text.startswith('Available'):
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAero(WhoisEntry):
    regex = {
        """Whois parser for .aero domains
        """
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'reseller': r'Reseller: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisGoogle(WhoisEntry):
    """Whois parser for Google domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAsia(WhoisEntry):
    """Whois parser for .asia domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'reseller': r'Reseller: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Domain not found.' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisTop(WhoisCom):
    """Whois parser for .top domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisBerlin(WhoisEntry):
    """Whois parser for .berlin domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'status': r'Domain Status: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDownload(WhoisEntry):
    """Whois parser for .download domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisFm(WhoisEntry):
    """Whois parser for .fm domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'status': r'Domain Status: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisGl(WhoisEntry):
    """Whois parser for .gl domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry RegistrantID: *(.+)',
        'registrant_name': r'RegistrantName: *(.+)',
        'registrant_org': r'RegistrantOrganization: *(.+)',
        'registrant_street': r'RegistrantStreet: *(.+)',
        'registrant_city': r'RegistrantCity: *(.+)',
        'registrant_state/province': r'RegistrantState/Province: *(.+)',
        'registrant_postal_code': r'RegistrantPostal Code: *(.+)',
        'registrant_country': r'RegistrantCountry: *(.+)',
        'registrant_phone': r'RegistrantPhone: *(.+)',
        'registrant_email': r'RegistrantEmail: *(.+)',
        'registry_admin_id': r'Registry AdminID: *(.+)',
        'admin_name': r'AdminName: *(.+)',
        'admin_org': r'AdminOrganization: *(.+)',
        'admin_street': r'AdminStreet: *(.+)',
        'admin_city': r'AdminCity: *(.+)',
        'admin_state/province': r'AdminState/Province: *(.+)',
        'admin_postal_code': r'AdminPostal Code: *(.+)',
        'admin_country': r'AdminCountry: *(.+)',
        'admin_phone': r'AdminPhone: *(.+)',
        'admin_email': r'AdminEmail: *(.+)',
        'registry_tech_id': r'Registry TechID: *(.+)',
        'tech_name': r'TechName: *(.+)',
        'tech_org': r'TechOrganization: *(.+)',
        'tech_street': r'TechStreet: *(.+)',
        'tech_city': r'TechCity: *(.+)',
        'tech_state/province': r'TechState/Province: *(.+)',
        'tech_postal_code': r'TechPostal Code: *(.+)',
        'tech_country': r'TechCountry: *(.+)',
        'tech_phone': r'TechPhone: *(.+)',
        'tech_email': r'TechEmail: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisLease(WhoisCom):
    """Whois parser for .lease domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisOne(WhoisCom):
    """Whois parser for .one domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPhoto(WhoisEntry):
    """Whois parser for .photo domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisReview(WhoisCom):
    """Whois parser for .review domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAmsterdam(WhoisCom):
    """Whois parser for .amsterdam domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAc(WhoisCom):
    """Whois parser for .ac domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisAg(WhoisEntry):
    """Whois parser for .ag domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'reseller': r'Reseller: *(.+)',
        'status': r'Domain Status: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCd(WhoisEntry):
    """Whois parser for .cd domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'reseller': r'Reseller: *(.+)',
        'status': r'Domain Status: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCi(WhoisEntry):
    """Whois parser for .ci domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCo(WhoisCom):
    """Whois parser for .co domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No Data Found' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisCx(WhoisEntry):
    """Whois parser for .cx domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisDm(WhoisEntry):
    """Whois parser for .dm domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisFo(WhoisEntry):
    """Whois parser for .fo domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'reseller': r'Reseller: *(.+)',
        'status': r'Domain Status: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisGd(WhoisEntry):
    """Whois parser for .gd domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'reseller': r'Reseller: *(.+)',
        'status': r'Domain Status: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisGe(WhoisEntry):
    """Whois parser for .ge domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registrant': r'Registrant: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisGq(WhoisEntry):
    """Whois parser for .gq domains
    """
    regex = {
        'creation_date': r'Domain registered: *(.+)',
        'expiration_date': r'Record will expire on: *(.+)',
        'registrar': r'Record maintained by: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisGs(WhoisEntry):
    """Whois parser for .gs domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisGy(WhoisEntry):
    """Whois parser for .gy domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisHt(WhoisEntry):
    """Whois parser for .ht domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Tech Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisKe(WhoisEntry):
    """Whois parser for .ke domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisKn(WhoisEntry):
    """Whois parser for .kn domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisKy(WhoisEntry):
    """Whois parser for .ky domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisKz(WhoisEntry):
    """Whois parser for .kz domains
    """
    regex = {
        'registrant_name': r'Name...................: *(.+)',
        'org_name': r'Organization Name......: *(.+)',
        'registrant_street': r'Street Address.........: *(.+)',
        'registrant_city': r'City...................: *(.+)',
        'registrant_state/province': r'State..................: *(.+)',
        'registrant_postal_code': r'Postal Code............: *(.+)',
        'registrant_country': r'Country................: *(.+)',

        'nic_handle': r'NIC Handle.............: *(.+)',
        'admin_phone': r'Phone Number...........: *(.+)',
        'admin_fax': r'Fax Number.............: *(.+)',
        'admin_email': r'Email Address..........: *(.+)',
        'name_servers': r'Primary server.........: *(.+)',
        'name_servers': r'Primary ip address.....: *(.+)',
        'name_servers': r'Secondary server.......: *(.+)',
        'name_servers': r'Secondary ip address...: *(.+)',
        'creation_date': r'Domain created: *(.+)',
        'updated_date': r'Last modified : *(.+)',
        'status': r'Domain status : *(.+)',
        'registrar': r'Current Registrar: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisLa(WhoisEntry):
    """Whois parser for .la domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'reseller': r'Reseller: *(.+)',
        'status': r'Domain Status: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisLc(WhoisEntry):
    """Whois parser for .lc domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'reseller': r'Reseller: *(.+)',
        'status': r'Domain Status: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisLy(WhoisEntry):
    """Whois parser for .ly domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar_registration_exp_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'reseller': r'Reseller: *(.+)',
        'status': r'Domain Status: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMa(WhoisEntry):
    """Whois parser for .ma domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'sponsoring_registrar': r'Sponsoring Registrar: *(.+)',
        'status': r'Domain Status: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMd(WhoisEntry):
    """Whois parser for .md domains
    """
    regex = {
        'domain_name': r'Domain   name: *(.+)',
        'domain_status': r'Domain  state: *(.+)',
        'creation_date': r'Registered on: *(.+)',
        'expiration_date': r'Expires    on: *(.+)',
        'name_servers': r'Nameserver: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMg(WhoisEntry):
    """Whois parser for .mg domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMn(WhoisCom):
    """Whois parser for .mn domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMs(WhoisEntry):
    """Whois parser for .ms domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMu(WhoisEntry):
    """Whois parser for .mu domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Domain ID: *(.+)',
        'registrar_whois_server': r'WHOIS Server: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNc(WhoisEntry):
    """Whois parser for .nc domains
    """
    regex = {
        'domain_name': r'Domain                   : *(.+)',
        'updated_date': r'Last updated on          : *(.+)',
        'creation_date': r'Created on               : *(.+)',
        'expiration_date': r'Expires on               : *(.+)',
        'registrar': r'Registrar: *(.+)',
        'name_servers': r'Domain server 1          : *(.+)',
        'name_servers': r'Domain server 2          : *(.+)',
        'name_servers': r'Domain server 3          : *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNg(WhoisEntry):
    """Whois parser for .ng domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisNf(WhoisEntry):
    """Whois parser for .nf domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisOm(WhoisEntry):
    """Whois parser for .om domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'updated_date': r'Last Modified: *(.+)',
        'registrar': r'Registrar Name: *(.+)',
        'status': r'Status: *(.+)',
        'registrant_name': r'Registrant Contact Name: *(.+)',
        'registrant_email': r'Registrant Contact Email: *(.+)',
        'registrant_org': r'Registrant Contact Organization: *(.+)',
        'registrant_city': r'Registrant Contact City: *(.+)',
        'registrant_country': r'Registrant Contact Country: *(.+)',
        'tech_name': r'Tech Contact Name: *(.+)',
        'tech_email': r'Tech Contact Email: *(.+)',
        'tech_org': r'Tech Contact Organization: *(.+)',
        'tech_city': r'Tech Contact City: *(.+)',
        'tech_country': r'Tech Contact Country: *(.+)',
        'name_servers': r'Name Server: *(.+)',
    }


class WhoisCentralNic(WhoisEntry):
    """Whois parser for CentralNic domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisParis(WhoisEntry):
    """Whois parser for .paris domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisParty(WhoisCom):
    """Whois parser for .party domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisTucows(WhoisEntry):
    """Whois parser for Tucows domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisPs(WhoisCom):
    """Whois parser for .ps domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisScience(WhoisCom):
    """Whois parser for .science domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisFashion(WhoisCom):
    """Whois parser for .fashion domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisMelbourne(WhoisCom):
    """Whois parser for .melbourne domains
    """

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisWales(WhoisEntry):
    """Whois parser for .wales domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'registry_billing_id': r'Registry Billing ID: *(.+)',
        'billing_name': r'Billing Name: *(.+)',
        'billing_org': r'Billing Organization: *(.+)',
        'billing_street': r'Billing Street: *(.+)',
        'billing_city': r'Billing City: *(.+)',
        'billing_state/province': r'Billing State/Province: *(.+)',
        'billing_postal_code': r'Billing Postal Code: *(.+)',
        'billing_country': r'Billing Country: *(.+)',
        'billing_phone': r'Billing Phone: *(.+)',
        'billing_fax': r'Billing Fax: *(.+)',
        'billing_email': r'Billing Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisIdentityDigitalInc(WhoisEntry):
    """Whois parser for Identity Digital Inc domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Registry Domain ID: *(.+)',
        'registrar_whois_server': r'Registrar WHOIS Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registry Expiry Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registry_registrant_id': r'Registry Registrant ID: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_org': r'Registrant Organization: *(.+)',
        'registrant_street': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state/province': r'Registrant State/Province: *(.+)',
        'registrant_postal_code': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_phone': r'Registrant Phone: *(.+)',
        'registrant_phone_ext': r'Registrant Phone Ext: *(.+)',
        'registrant_fax': r'Registrant Fax: *(.+)',
        'registrant_fax_ext': r'Registrant Fax Ext: *(.+)',
        'registrant_email': r'Registrant Email: *(.+)',
        'registry_admin_id': r'Registry Admin ID: *(.+)',
        'admin_name': r'Admin Name: *(.+)',
        'admin_org': r'Admin Organization: *(.+)',
        'admin_street': r'Admin Street: *(.+)',
        'admin_city': r'Admin City: *(.+)',
        'admin_state/province': r'Admin State/Province: *(.+)',
        'admin_postal_code': r'Admin Postal Code: *(.+)',
        'admin_country': r'Admin Country: *(.+)',
        'admin_phone': r'Admin Phone: *(.+)',
        'admin_phone_ext': r'Admin Phone Ext: *(.+)',
        'admin_fax': r'Admin Fax: *(.+)',
        'admin_fax_ext': r'Admin Fax Ext: *(.+)',
        'admin_email': r'Admin Email: *(.+)',
        'registry_tech_id': r'Registry Tech ID: *(.+)',
        'tech_name': r'Tech Name: *(.+)',
        'tech_org': r'Tech Organization: *(.+)',
        'tech_street': r'Tech Street: *(.+)',
        'tech_city': r'Tech City: *(.+)',
        'tech_state/province': r'Tech State/Province: *(.+)',
        'tech_postal_code': r'Tech Postal Code: *(.+)',
        'tech_country': r'Tech Country: *(.+)',
        'tech_phone': r'Tech Phone: *(.+)',
        'tech_phone_ext': r'Tech Phone Ext: *(.+)',
        'tech_fax': r'Tech Fax: *(.+)',
        'tech_fax_ext': r'Tech Fax Ext: *(.+)',
        'tech_email': r'Tech Email: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'url_of_icann_form': r'URL of the ICANN Whois Inaccuracy Complaint Form: *(.+)',
    }

    def __init__(self, domain, text):
        if 'Not found:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)


class WhoisWs(WhoisEntry):
    """Whois parser for .ws domains
    """
    regex = {
        'domain_name': r'Domain Name: *(.+)',
        'registry_domain_id': r'Domain ID: *(.+)',
        'whois_server': r'Whois Server: *(.+)',
        'registrar_url': r'Registrar URL: *(.+)',
        'updated_date': r'Updated Date: *(.+)',
        'creation_date': r'Creation Date: *(.+)',
        'expiration_date': r'Registrar Registration Expiration Date: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrar_iana_id': r'Registrar IANA ID: *(.+)',
        'registrar_abuse_contact_email': r'Registrar Abuse Contact Email: *(.+)',
        'registrar_abuse_contact_phone': r'Registrar Abuse Contact Phone: *(.+)',
        'status': r'Domain Status: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
    }

    def __init__(self, domain, text):
        if 'The queried object does not exist:' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)
