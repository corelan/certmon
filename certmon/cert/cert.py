#    certmon.py - Certificate Expiration monitor
#    Copyright (C) 2015 - Peter 'corelanc0d3r' Van Eeckhoutte - www.corelan.be
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import ssl
import OpenSSL
import datetime
import logging

log = logging.getLogger(__name__)

class Cert:
    def __init__(self, host=None, ip=None, port=None, fieldcheck=None):
        self.ip = ip
        self.port = port
        self.host = host
        self.fieldcheck = fieldcheck

        self.x509 = None
        self.certinfo = None

        # self.target = None
        # self.target_port = None
        # self.target_host = None
        # self.target_ip = None

        self.issuer = None
        self.serial = None
        self.subject = None
        self.version = None

        self.issuerok = True
        self.serialok = True
        self.subjectok = True
        self.versionok = True
        self.certchanged = False

        self.expire_date = None
        self.alertbefore_date = 30
        self.delta = None

        if ip != None and port != None:
            self.fetch()
            self.parse()

 
    def fetch(self):
        self.certinfo = ssl.get_server_certificate((self.ip, self.port))

    def parse(self):
        # Note - need to examine why the string replacement needs to happen
        certinfo = self.certinfo.replace("=-----END", "=\n-----END")
        self.x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certinfo)

        self.issuer = self.x509.get_issuer()
        self.serial = self.x509.get_serial_number()
        self.subject = self.x509.get_subject()
        self.version = self.x509.get_version()

        self._check_fields()
        self._parse_cert_datetime()

    def is_expired(self):
        self.delta = self.expire_date - self._curr_date()
        if self.delta.days < 0:
            log.info("\t*** CERTIFICATE HAS EXPIRED ON %s (%d days ago) ***" %
                  (self.expire_date, (self.delta.days * -1)))
            return True
        else:
            return False

    def is_alertbefore(self):
        self.delta = self.expire_date - self._curr_date()
        if self.delta.days == 0:
            log.info("*** CERTIFICATE EXPIRES TODAY ***")
            return True
        elif self.delta.days < self.alertbefore_date:
            log.info("** Warning: certificate will expire in less than %d days" % self.alertbefore_date)
            # NOTE return True xor False?!
            return True
        else:
            log.info("Cert expiration OK")
            log.info("Certificate will expire on %s (%d days from now)" % (self.expire_date, self.delta.days))
            return False

    def is_changed(self):
        self._check_fields()
        return self.certchanged

    def msg(self):
        #def createMsg(x509, targethost, targetport, targetip, expirdate, diff):
        msg = ""

        # NOTE handle the DIFF
        diff = self.delta.days
        extratxt = ""
        if diff < 0:
            extratxt = " ({} days ago)".format(diff * -1)
        else:
            extratxt = " (will expire in {} days)".format(diff)

        msg += "Host: {}, Port: {}, IP: {}\n".format(self.host, self.port, self.ip)
        msg += "  Subject: {}\n".format(self.subject)
        msg += "  Expiration date: {}{}\n".format(self.expire_date, extratxt)
        msg += "  Issuer: {}\n".format(self.issuer)
        msg += "  Version: {}\n".format(self.version)
        msg += "  Serial: {}\n".format(self.serial)

        if not self.subjectok:
            log.info("Subject field contains '%s'" % subject)
            log.info("Expected to contain: '%s'" % fieldcheck["subject"])
            thismsg += "** Subject field does not contain '{}'\n".format(fieldcheck["subject"])
        if not self.issuerok:
            log.info("Issuer field contains '%s'" % issuer)
            log.info("Expected to contain: '%s'" %fieldcheck["issuer"])
            thismsg += "** Issuer field does not contain '{}'\n".format(fieldcheck["issuer"])
        if not self.versionok:
            log.info("Version field contains '%s'" % version)
            log.info("Expected to contain: '%s'" % fieldcheck["version"])
            thismsg += "** Version field does not contain '{}'\n".format(fieldcheck["version"])
        if not self.serialok:
            log.info("Serial field contains '%s'" % serial)
            log.info("Expected to contain: '%s'" % fieldcheck["serial"])
            thismsg += "** Serial field does not contain '{}'\n".format(fieldcheck["serial"])

        return msg

    def _check_fields(self):
        for fieldname in self.fieldcheck:
            if fieldname == "issuer":
                if not self.fieldcheck[fieldname] in str(self.issuer).lower():
                    self.issuerok = False
                    self.certchanged = True
            elif fieldname == "subject":
                if not self.fieldcheck[fieldname] in str(self.subject).lower():
                    self.subjectok = False
                    self.certchanged = True
            elif fieldname == "version":
                if not self.fieldcheck[fieldname] in str(self.version).lower():
                    self.versionok = False
                    self.certchanged = True
            elif fieldname == "serial":
                if not self.fieldcheck[fieldname] in str(self.serial).lower():
                    self.serialok = False
                    self.certchanged = True

    def _curr_date(self):
        return datetime.datetime.now()

    def _parse_cert_datetime(self):
        expire_date_str = str(self.x509.get_notAfter()).replace("b'", "").replace("'", "")
        self.expire_date = datetime.datetime.strptime(expire_date_str, "%Y%m%d%H%M%SZ")


    def _show_verbose(self):
        pass