class Cert:
    def __init__(self, ip=None, port=None, fieldcheck=None):
        self.ip = ip
        self.port = port
        self.fieldcheck = fieldcheck

        self.x509 = None
        self.certinfo = None

        self.target = None
        self.target_port = None
        self.target_host = None
        self.target_ip = None

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
            print("    *** CERTIFICATE HAS EXPIRED ON %s (%d days ago) ***" %
                  (self.expire_date, (self.delta.days * -1)))
            return True
        else:
            return False

    def is_alertbefore(self):
        self.delta = self.expire_date - self._curr_date()
        if self.delta.days == 0:
            print("    *** CERTIFICATE EXPIRES TODAY ***")
            return True
        elif self.delta.days < self.alertbefore_date:
            print("    ** Warning: certificate will expire in less than %d days" % self.alertbefore_date)
            # NOTE return True xor False?!
            return True
        else:
            print("    Cert expiration OK")
            print("    Note: Certificate will expire on %s (%d days from now)" % (self.expire_date, self.delta.days))
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

        msg += "Host: {}, Port: {}, IP: {}\n".format(self.target_host, self.target_port, self.target_ip)
        msg += "  Subject: {}\n".format(self.subject)
        msg += "  Expiration date: {}{}\n".format(self.expire_date, extratxt)
        msg += "  Issuer: {}\n".format(self.issuer)
        msg += "  Version: {}\n".format(self.version)
        msg += "  Serial: {}\n".format(self.serial)

        if not cert.subjectok:
            print("    Subject field contains '%s'" % subject)
            print("    Expected to contain: '%s'" % fieldcheck["subject"])
            thismsg += "** Subject field does not contain '{}'\n".format(fieldcheck["subject"])
        if not cert.issuerok:
            print("    Issuer field contains '%s'" % issuer)
            print("    Expected to contain: '%s'" %fieldcheck["issuer"])
            thismsg += "** Issuer field does not contain '{}'\n".format(fieldcheck["issuer"])
        if not cert.versionok:
            print("    Version field contains '%s'" % version)
            print("    Expected to contain: '%s'" % fieldcheck["version"])
            thismsg += "** Version field does not contain '{}'\n".format(fieldcheck["version"])
        if not cert.serialok:
            print("    Serial field contains '%s'" % serial)
            print("      Expected to contain: '%s'" % fieldcheck["serial"])
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