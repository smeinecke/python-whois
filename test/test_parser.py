# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_aliases()
from builtins import *
import unittest

import os
import sys
sys.path.append('../')

import datetime

try:
    import json
except:
    import simplejson as json
from glob import glob

from whois.parser import WhoisEntry, cast_date, WhoisCl, WhoisAr, WhoisBy, \
    WhoisCa, WhoisBiz, WhoisCr, WhoisDe, WhoisNl, WhoisEdu


class TestParser(unittest.TestCase):

    def test_com_expiration(self):
        data = """
        Status: ok
        Updated Date: 2017-03-31T07:36:34Z
        Creation Date: 2013-02-21T19:24:57Z
        Registry Expiry Date: 2018-02-21T19:24:57Z

        >>> Last update of whois database: Sun, 31 Aug 2008 00:18:23 UTC <<<
        """
        w = WhoisEntry.load('urlowl.com', data)
        expires = w.expiration_date.strftime('%Y-%m-%d')
        self.assertEqual(expires, '2018-02-21')

    def test_cast_date(self):
        dates = ['14-apr-2008', '2008-04-14']
        for d in dates:
            r = cast_date(d).strftime('%Y-%m-%d')
            self.assertEqual(r, '2008-04-14')

    def test_com_allsamples(self):
        """
        Iterate over all of the sample/whois/*.com files, read the data,
        parse it, and compare to the expected values in sample/expected/.
        Only keys defined in keys_to_test will be tested.

        To generate fresh expected value dumps, see NOTE below.
        """
        keys_to_test = ['domain_name', 'expiration_date', 'updated_date',
                        'registrar', 'registrar_url', 'creation_date', 'status']
        fail = 0
        total = 0
        whois_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),'samples','whois','*')
        expect_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples','expected')
        for path in glob(whois_path):
            # Parse whois data
            domain = os.path.basename(path)
            with open(path) as whois_fp:
                data = whois_fp.read()

            w = WhoisEntry.load(domain, data)
            results = {key: w.get(key) for key in keys_to_test}

            # NOTE: Toggle condition below to write expected results from the
            # parse results This will overwrite the existing expected results.
            # Only do this if you've manually confirmed that the parser is
            # generating correct values at its current state.
            if False:
                def date2str4json(obj):
                    if isinstance(obj, datetime.datetime):
                        return str(obj)
                    raise TypeError(
                            '{} is not JSON serializable'.format(repr(obj)))
                outfile_name = os.path.join(expect_path, domain)
                with open(outfile_name, 'w') as outfil:
                    expected_results = json.dump(results, outfil,
                                                       default=date2str4json)
                continue

            # Load expected result
            with open(os.path.join(expect_path, domain)) as infil:
                expected_results = json.load(infil)

            # Compare each key
            compare_keys = set.union(set(results), set(expected_results))
            if keys_to_test is not None:
                compare_keys = compare_keys.intersection(set(keys_to_test))
            for key in compare_keys:
                total += 1
                if key not in results:
                    print("%s \t(%s):\t Missing in results" % (domain, key,))
                    fail += 1
                    continue

                result = results.get(key)
                if isinstance(result, list):
                    result = [str(element) for element in result]
                if isinstance(result, datetime.datetime):
                    result = str(result)
                expected = expected_results.get(key)
                if expected != result:
                    print("%s \t(%s):\t %s != %s" % (domain, key, result, expected))
                    fail += 1

        if fail:
            self.fail("%d/%d sample whois attributes were not parsed properly!"
                      % (fail, total))

    def test_ca_parse(self):
        data = """
        Domain name:           testdomain.ca
        Domain status:         registered
        Creation date:         2000/11/20
        Expiry date:           2020/03/08
        Updated date:          2016/04/29
        DNSSEC:                Unsigned

        Registrar:             Webnames.ca Inc.
        Registry Registrant ID: 70

        Registrant Name:       Test Industries
        Registrant Organization:

        Admin Name:            Test Person1
        Admin Street:          Test Address
        Admin City:            Test City, TestVille
        Admin Phone:           +1.1235434123x123
        Admin Fax:             +1.123434123
        Admin Email:           testperson1@testcompany.ca

        Tech Name:             Test Persion2
        Tech Street:           Other TestAddress
                               TestTown OCAS Canada
        Tech Phone:            +1.09876545123
        Tech Fax:              +1.12312993873
        Tech Email:            testpersion2@testcompany.ca

        Name server:           a1-1.akam.net
        Name server:           a2-2.akam.net
        Name server:           a3-3.akam.net
        """
        expected_results = {
            "updated_date": "2016-04-29 00:00:00",
            "registrant_name": "Test Industries",
            "fax": [
                "+1.123434123",
                "+1.12312993873"
            ],
            "dnssec": "Unsigned",
            "registrant_number": "70",
            "expiration_date": "2020-03-08 00:00:00",
            "domain_name": "testdomain.ca",
            "creation_date": "2000-11-20 00:00:00",
            "phone": [
                "+1.1235434123x123",
                "+1.09876545123"
            ],
            "status": "registered",
            "emails": [
                "testperson1@testcompany.ca",
                "testpersion2@testcompany.ca"
            ]
        }
        self._parse_and_compare('testcompany.ca', data, expected_results,
                                whois_entry=WhoisCa)

    def test_edu_parse(self):
        data = """
        % IANA WHOIS server
        % for more information on IANA, visit http://www.iana.org
        % This query returned 1 object

        refer:        whois.educause.edu

        domain:       EDU

        organisation: EDUCAUSE
        address:      282 Century Place, Suite 5000
        address:      Louisville CO 80027
        address:      United States of America (the)

        contact:      administrative
        name:         Information Services Administration
        organisation: EDUCAUSE
        address:      4772 Walnut Street, Suite 206
        address:      Boulder CO 80301
        address:      United States of America (the)
        phone:        +1-303-449-4430
        fax-no:       +1-303-440-0461
        e-mail:       netadmin@educause.edu

        contact:      technical
        name:         Registry Customer Service
        organisation: VeriSign Global Registry
        address:      12061 Bluemont Way
        address:      Reston VA 20190
        address:      United States of America (the)
        phone:        +1-703-925-6999
        fax-no:       +1-703-948-3978
        e-mail:       info@verisign-grs.com

        nserver:      A.EDU-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30
        nserver:      B.EDU-SERVERS.NET 192.33.14.30 2001:503:231d:0:0:0:2:30
        nserver:      C.EDU-SERVERS.NET 192.26.92.30 2001:503:83eb:0:0:0:0:30
        nserver:      D.EDU-SERVERS.NET 192.31.80.30 2001:500:856e:0:0:0:0:30
        nserver:      E.EDU-SERVERS.NET 192.12.94.30 2001:502:1ca1:0:0:0:0:30
        nserver:      F.EDU-SERVERS.NET 192.35.51.30 2001:503:d414:0:0:0:0:30
        nserver:      G.EDU-SERVERS.NET 192.42.93.30 2001:503:eea3:0:0:0:0:30
        nserver:      H.EDU-SERVERS.NET 192.54.112.30 2001:502:8cc:0:0:0:0:30
        nserver:      I.EDU-SERVERS.NET 192.43.172.30 2001:503:39c1:0:0:0:0:30
        nserver:      J.EDU-SERVERS.NET 192.48.79.30 2001:502:7094:0:0:0:0:30
        nserver:      K.EDU-SERVERS.NET 192.52.178.30 2001:503:d2d:0:0:0:0:30
        nserver:      L.EDU-SERVERS.NET 192.41.162.30 2001:500:d937:0:0:0:0:30
        nserver:      M.EDU-SERVERS.NET 192.55.83.30 2001:501:b1f9:0:0:0:0:30
        ds-rdata:     28065 8 2 4172496cde85534e51129040355bd04b1fcfebae996dfdde652006f6f8b2ce76

        whois:        whois.educause.edu

        status:       ACTIVE
        remarks:      Registration information:
        remarks:      http://www.educause.edu/edudomain

        created:      1985-01-01
        changed:      2022-05-06
        source:       IANA

        # whois.educause.edu

        This Registry database contains ONLY .EDU domains.
        The data in the EDUCAUSE Whois database is provided
        by EDUCAUSE for information purposes in order to
        assist in the process of obtaining information about
        or related to .edu domain registration records.

        The EDUCAUSE Whois database is authoritative for the
        .EDU domain.

        A Web interface for the .EDU EDUCAUSE Whois Server is
        available at: http://whois.educause.edu

        By submitting a Whois query, you agree that this information
        will not be used to allow, enable, or otherwise support
        the transmission of unsolicited commercial advertising or
        solicitations via e-mail.  The use of electronic processes to
        harvest information from this server is generally prohibited
        except as reasonably necessary to register or modify .edu
        domain names.

        -------------------------------------------------------------

        Domain Name: USF.EDU

        Registrant:
            University of South Florida
            Information Technology
            4202 E. Fowler Avenue, SVC 4010
            Tampa, FL 33620
            USA

        Administrative Contact:
            Domain Admin
            University of South Florida
            Information Technology
            4202 E. Fowler Avenue, SVC 4010
            Tampa, FL 33620
            USA
            +1.8139741793
            ted@usf.edu

        Technical Contact:
            Eric Stewart
            University of South Florida
            Information Technology
            4202 E. Fowler Avenue, SVC 4010
            Tampa, FL 33620
            USA
            +1.8139746084
            eric@usf.edu

        Name Servers:
            MOTHER.USF.EDU
            AZURE-DR-BNS1.USF.EDU
            ZIGGY.USF.EDU

        Domain record activated:    29-Sep-1986
        Domain record last updated: 01-Feb-2022
        Domain expires:             31-Jul-2024"""
        expected_results = {
            "domain_name": "USF.EDU",
            "registrar": "VeriSign Global Registry",
            "whois_server": "whois.educause.edu",
            "referral_url": "whois.educause.edu",
            "updated_date": "2022-02-01 00:00:00",
            "creation_date": "1986-09-29 00:00:00",
            "expiration_date": "2024-07-31 00:00:00",
            "emails": ['netadmin@educause.edu', 'info@verisign-grs.com', 'ted@usf.edu', 'eric@usf.edu'],
            "name_servers": ["MOTHER.USF.EDU", "AZURE-DR-BNS1.USF.EDU", "ZIGGY.USF.EDU"],
            "status": "ACTIVE",
            "registrant_name": "University of South Florida",
        }
        self._parse_and_compare('usf.edu', data, expected_results,
                                whois_entry=WhoisEdu)
    def test_ai_parse(self):
        data = """
Domain Name: google.ai
Registry Domain ID: 325702_nic_ai
Registry WHOIS Server: whois.nic.ai
Creation Date: 2017-12-16T05:37:20.801Z
Registrar: Markmonitor
Registrar Abuse Contact Email: ccops@markmonitor.com
Registrar Abuse Contact Phone: +1.2083895740
Registry RegistrantID: Vlmri-g0QZU
RegistrantName: Domain Administrator
RegistrantOrganization: Google LLC
RegistrantStreet: 1600 Amphitheatre Parkway
RegistrantCity: Mountain View
RegistrantState/Province: CA
RegistrantPostal Code: 94043
RegistrantCountry: US
RegistrantPhone: +1.6502530000
RegistrantFax: +1.6502530001
RegistrantEmail: dns-admin@google.com
Registry AdminID: F4699-Tinjk
AdminName: Domain Administrator
AdminOrganization: Google LLC
AdminStreet: 1600 Amphitheatre Parkway
AdminCity: Mountain View
AdminState/Province: CA
AdminPostal Code: 94043
AdminCountry: US
AdminPhone: +1.6502530000
AdminFax: +1.6502530001
AdminEmail: dns-admin@google.com
Registry TechID: htY0V-EnRVF
TechName: Domain Administrator
TechOrganization: Google LLC
TechStreet: 1600 Amphitheatre Parkway
TechCity: Mountain View
TechState/Province: CA
TechPostal Code: 94043
TechCountry: US
TechPhone: +1.6502530000
TechFax: +1.6502530001
TechEmail: dns-admin@google.com
Registry BillingID: REFum-eZX0X
BillingName: CCOPS Billing
BillingOrganization: MarkMonitor Inc.
BillingStreet: 3540 East Longwing Lane
BillingStreet: Suite 300
BillingCity: Meridian
BillingState/Province: Idaho
BillingPostal Code: 83646
BillingCountry: US
BillingPhone: +1.2083895740
BillingFax: +1.2083895771
BillingEmail: ccopsbilling@markmonitor.com
Name Server: ns3.zdns.google
Name Server: ns4.zdns.google
Name Server: ns1.zdns.google
Name Server: ns2.zdns.google
DNSSEC: unsigned
        """

        expected_results = {
             'admin_address': '1600 Amphitheatre Parkway',
             'admin_city': 'Mountain View',
             'admin_country': 'US',
             'admin_email': 'dns-admin@google.com',
             'admin_name': 'Domain Administrator',
             'admin_org': 'Google LLC',
             'admin_phone': '+1.6502530000',
             'admin_postal_code': '94043',
             'admin_state': 'CA',
             'billing_address': ['3540 East Longwing Lane', 'Suite 300'],
             'billing_city': 'Meridian',
             'billing_country': 'US',
             'billing_email': 'ccopsbilling@markmonitor.com',
             'billing_name': 'CCOPS Billing',
             'billing_org': 'MarkMonitor Inc.',
             'billing_phone': '+1.2083895740',
             'billing_postal_code': '83646',
             'billing_state': 'Idaho',
             'creation_date': str(datetime.datetime(2017, 12, 16, 5, 37, 20, 801000)),
             'domain_id': '325702_nic_ai',
             'domain_name': 'google.ai',
             'name_servers': ['ns3.zdns.google',
                              'ns4.zdns.google',
                              'ns1.zdns.google',
                              'ns2.zdns.google'],
             'registrant_address': '1600 Amphitheatre Parkway',
             'registrant_city': 'Mountain View',
             'registrant_country': 'US',
             'registrant_email': 'dns-admin@google.com',
             'registrant_name': 'Domain Administrator',
             'registrant_org': 'Google LLC',
             'registrant_phone': '+1.6502530000',
             'registrant_postal_code': '94043',
             'registrant_state': 'CA',
             'registrar': 'Markmonitor',
             'registrar_email': 'ccops@markmonitor.com',
             'registrar_phone': '+1.2083895740',
             'tech_address': '1600 Amphitheatre Parkway',
             'tech_city': 'Mountain View',
             'tech_country': 'US',
             'tech_email': 'dns-admin@google.com',
             'tech_name': 'Domain Administrator',
             'tech_org': 'Google LLC',
             'tech_phone': '+1.6502530000',
             'tech_postal_code': '94043',
             'tech_state': 'CA'}
        self._parse_and_compare('google.ai', data, expected_results)


    def test_cn_parse(self):
        data = """
            Domain Name: cnnic.com.cn
            ROID: 20021209s10011s00047242-cn
            Domain Status: serverDeleteProhibited
            Domain Status: serverUpdateProhibited
            Domain Status: serverTransferProhibited
            Registrant ID: s1255673574881
            Registrant: 中国互联网络信息中心
            Registrant Contact Email: servicei@cnnic.cn
            Sponsoring Registrar: 北京新网数码信息技术有限公司
            Name Server: a.cnnic.cn
            Name Server: b.cnnic.cn
            Name Server: c.cnnic.cn
            Name Server: d.cnnic.cn
            Name Server: e.cnnic.cn
            Registration Time: 2000-09-14 00:00:00
            Expiration Time: 2023-08-16 16:26:39
            DNSSEC: unsigned
        """
        expected_results = {
            "domain_name": "cnnic.com.cn",
            "registrar": "北京新网数码信息技术有限公司",
            "creation_date": "2000-09-14 00:00:00",
            "expiration_date": "2023-08-16 16:26:39",
            "name_servers": ["a.cnnic.cn", "b.cnnic.cn", "c.cnnic.cn", "d.cnnic.cn", "e.cnnic.cn"],
            "status": ["serverDeleteProhibited", "serverUpdateProhibited", "serverTransferProhibited"],
            "emails": "servicei@cnnic.cn",
            "dnssec": "unsigned",
            "name": "中国互联网络信息中心"
        }
        self._parse_and_compare('cnnic.com.cn', data, expected_results)

    def test_il_parse(self):
        data = """
            query:        python.org.il

            reg-name:     python
            domain:       python.org.il

            descr:        Arik Baratz
            descr:        PO Box 7775 PMB 8452
            descr:        San Francisco, CA
            descr:        94120
            descr:        USA
            phone:        +1 650 6441973
            e-mail:       hostmaster AT arik.baratz.org
            admin-c:      LD-AB16063-IL
            tech-c:       LD-AB16063-IL
            zone-c:       LD-AB16063-IL
            nserver:      dns1.zoneedit.com
            nserver:      dns2.zoneedit.com
            nserver:      dns3.zoneedit.com
            validity:     10-05-2018
            DNSSEC:       unsigned
            status:       Transfer Locked
            changed:      domain-registrar AT isoc.org.il 20050524 (Assigned)
            changed:      domain-registrar AT isoc.org.il 20070520 (Transferred)
            changed:      domain-registrar AT isoc.org.il 20070520 (Changed)
            changed:      domain-registrar AT isoc.org.il 20070520 (Changed)
            changed:      domain-registrar AT isoc.org.il 20070807 (Changed)
            changed:      domain-registrar AT isoc.org.il 20071025 (Changed)
            changed:      domain-registrar AT isoc.org.il 20071025 (Changed)
            changed:      domain-registrar AT isoc.org.il 20081221 (Changed)
            changed:      domain-registrar AT isoc.org.il 20081221 (Changed)
            changed:      domain-registrar AT isoc.org.il 20160301 (Changed)
            changed:      domain-registrar AT isoc.org.il 20160301 (Changed)

            person:       Arik Baratz
            address:      PO Box 7775 PMB 8452
            address:      San Francisco, CA
            address:      94120
            address:      USA
            phone:        +1 650 9635533
            e-mail:       hostmaster AT arik.baratz.org
            nic-hdl:      LD-AB16063-IL
            changed:      Managing Registrar 20070514
            changed:      Managing Registrar 20081002
            changed:      Managing Registrar 20081221
            changed:      Managing Registrar 20081221
            changed:      Managing Registrar 20090502

            registrar name: LiveDns Ltd
            registrar info: http://domains.livedns.co.il
        """
        expected_results = {
            "updated_date": None,
            "registrant_name": "Arik Baratz",
            "fax": None,
            "dnssec": "unsigned",
            "expiration_date": "2018-05-10 00:00:00",
            "domain_name": "python.org.il",
            "creation_date": None,
            "phone": ['+1 650 6441973', '+1 650 9635533'],
            "status": "Transfer Locked",
            "emails": "hostmaster@arik.baratz.org",
            "name_servers": ["dns1.zoneedit.com", "dns2.zoneedit.com", "dns3.zoneedit.com"],
            "registrar": "LiveDns Ltd",
            "referral_url": "http://domains.livedns.co.il"
        }
        self._parse_and_compare('python.org.il', data, expected_results)

    def test_ie_parse(self):
        data = """
        refer:        whois.weare.ie

domain:       IE

organisation: University College Dublin
organisation: Computing Services
organisation: Computer Centre
address:      Belfield
address:      Dublin City,  Dublin 4
address:      Ireland

contact:      administrative
name:         Chief Executive
organisation: IE Domain Registry Limited
address:      2 Harbour Square
address:      Dún Laoghaire
address:      Co. Dublin
address:      Ireland
phone:        +353 1 236 5412
fax-no:       +353 1 230 1273
e-mail:       tld-admin@weare.ie

contact:      technical
name:         Technical Services Manager
organisation: IE Domain Registry Limited
address:      2 Harbour Square
address:      Dún Laoghaire
address:      Co. Dublin
address:      Ireland
phone:        +353 1 236 5421
fax-no:       +353 1 230 1273
e-mail:       tld-tech@weare.ie

nserver:      B.NS.IE 2a01:4b0:0:0:0:0:0:2 77.72.72.34
nserver:      C.NS.IE 194.146.106.98 2001:67c:1010:25:0:0:0:53
nserver:      D.NS.IE 2a01:3f0:0:309:0:0:0:53 77.72.229.245
nserver:      G.NS.IE 192.111.39.100 2001:7c8:2:a:0:0:0:64
nserver:      H.NS.IE 192.93.0.4 2001:660:3005:1:0:0:1:2
nserver:      I.NS.IE 194.0.25.35 2001:678:20:0:0:0:0:35
ds-rdata:     64134 13 2 77B9519D16B62D0A70A7301945CBB3092A7978BFDE75A3BCFB3D4719396E436A

whois:        whois.weare.ie

status:       ACTIVE
remarks:      Registration information: http://www.weare.ie

created:      1988-01-27
changed:      2021-03-11
source:       IANA

# whois.weare.ie

Domain Name: rte.ie
Registry Domain ID: 672279-IEDR
Registrar WHOIS Server: whois.weare.ie
Registrar URL: https://www.blacknight.com
Updated Date: 2020-11-15T17:55:24Z
Creation Date: 2000-02-11T00:00:00Z
Registry Expiry Date: 2025-03-31T13:20:07Z
Registrar: Blacknight Solutions
Registrar IANA ID: not applicable
Registrar Abuse Contact Email: abuse@blacknight.com
Registrar Abuse Contact Phone: +353.599183072
Domain Status: ok https://icann.org/epp#ok
Registry Registrant ID: 354955-IEDR
Registrant Name: RTE Commercial Enterprises Limited
Registry Admin ID: 202753-IEDR
Registry Tech ID: 3159-IEDR
Registry Billing ID: REDACTED FOR PRIVACY
Name Server: ns1.rte.ie
Name Server: ns2.rte.ie
Name Server: ns3.rte.ie
Name Server: ns4.rte.ie
DNSSEC: signedDelegation
        """

        aexpected_results = {
            "domain_name": "rte.ie",
            "description": [
                "RTE Commercial Enterprises Limited",
                "Body Corporate (Ltd,PLC,Company)",
                "Corporate Name"
            ],
            "source": "IEDR",
            "creation_date": "2000-02-11 00:00:00",
            "expiration_date": "2024-03-31 00:00:00",
            "name_servers": [
                "ns1.rte.ie 162.159.0.73 2400:cb00:2049:1::a29f:49",
                "ns2.rte.ie 162.159.1.73 2400:cb00:2049:1::a29f:149",
                "ns3.rte.ie 162.159.2.27 2400:cb00:2049:1::a29f:21b",
                "ns4.rte.ie 162.159.3.18 2400:cb00:2049:1::a29f:312"
            ],
            "status": "Active",
            "admin_id": [
                "AWB910-IEDR",
                "JM474-IEDR"
            ],
            "tech_id": "JM474-IEDR"
        }
        expected_results = {
          "status": "ok https://icann.org/epp#ok",
          "expiration_date": "2025-03-31 13:20:07",
          "creation_date": "2000-02-11 00:00:00",
          "domain_name": "rte.ie",
          "tech_id": "3159-IEDR",
          "registrar": "Blacknight Solutions",
          "name_servers": [
            "ns1.rte.ie",
            "ns2.rte.ie",
            "ns3.rte.ie",
            "ns4.rte.ie"
          ],
          "admin_id": "202753-IEDR",
          "registrar_contact": "abuse@blacknight.com"
        }
        self._parse_and_compare('rte.ie', data, expected_results)

    def test_nl_parse(self):
        data = """
        Domain name: utwente.nl
        Status:      active

        Registrar:
           Universiteit Twente
           Drienerlolaan 5
           7522NB ENSCHEDE
           Netherlands

        Abuse Contact:

        DNSSEC:      yes

        Domain nameservers:
           ns3.utwente.nl          131.155.0.37
           ns1.utwente.nl          130.89.1.2
           ns1.utwente.nl          2001:67c:2564:a102::3:1
           ns2.utwente.nl          130.89.1.3
           ns2.utwente.nl          2001:67c:2564:a102::3:2

        Record maintained by: NL Domain Registry
        """

        expected_results = {
            "domain_name": "utwente.nl",
            "name_servers": [
                "ns1.utwente.nl",
                "ns2.utwente.nl",
                "ns3.utwente.nl",
            ],
            "status": "active",
            'registrar_address': 'Drienerlolaan 5',
            'registrar': 'Universiteit Twente',
            'registrar_postal_code': '7522NB',
            'registrar_city': 'ENSCHEDE',
            'registrar_country': 'Netherlands',
            'dnssec': 'yes'
        }
        self._parse_and_compare('utwente.nl', data, expected_results)

    def test_nl_expiration(self):
        data = """
        domain_name: randomtest.nl
        Status:      in quarantine
        Creation Date: 2008-09-24
        Updated Date: 2020-10-27
        Date out of quarantine: 2020-12-06T20:31:25
        """

        w = WhoisEntry.load('randomtest.nl', data)
        expires = w.expiration_date.strftime('%Y-%m-%d')
        self.assertEqual(expires, '2020-12-06')

    def test_dk_parse(self):
        data = """
#
# Copyright (c) 2002 - 2019 by DK Hostmaster A/S
#
# Version:
#
# The data in the DK Whois database is provided by DK Hostmaster A/S
# for information purposes only, and to assist persons in obtaining
# information about or related to a domain name registration record.
# We do not guarantee its accuracy. We will reserve the right to remove
# access for entities abusing the data, without notice.
#
# Any use of this material to target advertising or similar activities
# are explicitly forbidden and will be prosecuted. DK Hostmaster A/S
# requests to be notified of any such activities or suspicions thereof.

Domain:               dk-hostmaster.dk
DNS:                  dk-hostmaster.dk
Registered:           1998-01-19
Expires:              2022-03-31
Registration period:  5 years
VID:                  yes
Dnssec:               Signed delegation
Status:               Active

Registrant
Handle:               DKHM1-DK
Name:                 DK HOSTMASTER A/S
Address:              Ørestads Boulevard 108, 11.
Postalcode:           2300
City:                 København S
Country:              DK

Nameservers
Hostname:             auth01.ns.dk-hostmaster.dk
Hostname:             auth02.ns.dk-hostmaster.dk
Hostname:             p.nic.dk
"""

        expected_results = {
            "domain_name": "dk-hostmaster.dk",
            "name_servers": [
                'auth01.ns.dk-hostmaster.dk',
                'auth02.ns.dk-hostmaster.dk',
                'p.nic.dk'
            ],
            "status": "Active",
            'registrant_name': 'DK HOSTMASTER A/S',
            'registrant_address': 'Ørestads Boulevard 108, 11.',
            'registrant_postal_code': '2300',
            'registrant_city': 'København S',
            'registrant_country': 'DK',
            'dnssec': 'Signed delegation'
        }
        self._parse_and_compare('dk-hostmaster.dk', data, expected_results)

    def _parse_and_compare(self, domain_name, data, expected_results, whois_entry=WhoisEntry):
        results = whois_entry.load(domain_name, data)
        if domain_name=='google.ai':
            print(results)
        fail = 0
        total = 0
        # Compare each key
        for key in expected_results:
            total += 1
            result = results.get(key)
            if isinstance(result, datetime.datetime):
                result = str(result)
            expected = expected_results.get(key)
            if expected != result:
                print("%s \t(%s):\t %s != %s" % (domain_name, key, result, expected))
                fail += 1
        if fail:
            self.fail("%d/%d sample whois attributes were not parsed properly!"
                      % (fail, total))

    def test_sk_parse(self):
        data = """
        # whois.sk-nic.sk

        Domain:                       pipoline.sk
        Registrant:                   H410977
        Admin Contact:                H410977
        Tech Contact:                 H410977
        Registrar:                    PIPO-0002
        Created:                      2012-07-23
        Updated:                      2020-07-02
        Valid Until:                  2021-07-13
        Nameserver:                   ns1.cloudlikeaboss.com
        Nameserver:                   ns2.cloudlikeaboss.com
        EPP Status:                   ok

        Registrar:                    PIPO-0002
        Name:                         Pipoline s.r.o.
        Organization:                 Pipoline s.r.o.
        Organization ID:              48273317
        Phone:                        +421.949347169
        Email:                        peter.gonda@pipoline.com
        Street:                       Ladožská 8
        City:                         Košice
        Postal Code:                  040 12
        Country Code:                 SK
        Created:                      2017-09-01
        Updated:                      2020-07-02

        Contact:                      H410977
        Name:                         Ing. Peter Gonda
        Organization:                 Pipoline s.r.o
        Organization ID:              48273317
        Email:                        info@pipoline.com
        Street:                       Ladozska 8
        City:                         Kosice
        Postal Code:                  04012
        Country Code:                 SK
        Registrar:                    PIPO-0002
        Created:                      2017-11-22
        Updated:                      2017-11-22"""

        expected_results = {
            'admin': 'H410977',
            'admin_city': 'Kosice',
            'admin_country_code': 'SK',
            'admin_email': 'info@pipoline.com',
            'admin_organization': 'Pipoline s.r.o',
            'admin_postal_code': '04012',
            'admin_street': 'Ladozska 8',
            'creation_date': '2012-07-23 00:00:00',
            'domain_name': 'pipoline.sk',
            'expiration_date': '2021-07-13 00:00:00',
            'name_servers': ['ns1.cloudlikeaboss.com', 'ns2.cloudlikeaboss.com'],
            'registrar': 'Pipoline s.r.o.',
            'registrar_city': 'Košice',
            'registrar_country_code': 'SK',
            'registrar_created': '2012-07-23',
            'registrar_email': 'peter.gonda@pipoline.com',
            'registrar_name': 'Pipoline s.r.o.',
            'registrar_organization_id': '48273317',
            'registrar_phone': '+421.949347169',
            'registrar_postal_code': '040 12',
            'registrar_street': 'Ladožská 8',
            'registrar_updated': '2020-07-02',
            'updated_date': '2020-07-02 00:00:00'}

        self._parse_and_compare('pipoline.sk', data, expected_results)


if __name__ == '__main__':
    unittest.main()