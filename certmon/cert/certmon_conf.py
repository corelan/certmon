class CertmonConf:

    def __init__(self, certconfig_filename=''):
        self.serverlist = []
        self.records = []
        self.certconfigfile = None

        if certconfig_filename != '':
            self.load(certconfig_filename)

    def open(self, certconfig_filename=''):
        if os.path.isfile(certconfig_filename):
            self.certconfigfile = open(certconfig_filename, "r")
        else:
            print("[-] Oops, file {} does not exist".format(certconfig_filename))
            print("    Desired format:    host:port   (one entry per line)")

    def close(self):
        self.certconfigfile.close()

    def load(self, certconfig_filename=''):
        # NOTE not sure if should be checking for just str xor unicode
        if certconfig_filename == None or not isinstance(certconfig_filename, str):
            # NOTE probably should rais an error here
            return
        # NOTE should verify is string
        self.open(certconfig_filename)
        self._parse()
        self.close()

    def _parse(self):
        content = self.certconfigfile.readlines()
        for l in content:
            checkdata = []
            lstripped = l.replace("\n", "").replace("\r", "").replace("\t", "")
            if not lstripped.startswith("#") and len(l) > 0:
                lineparts = lstripped.split(";")

                targetparts = lineparts[0].split(":")

                rport = 443
                rhost = targetparts[0]
                if len(targetparts) > 1:
                    try:
                        rport = int(targetparts[1])
                    except:
                        pass

                check = ""
                if len(lineparts) > 1:
                    i = 1
                    while i < len(lineparts):
                        checkdata.append(lineparts[i])
                        i += 1

                thisserver = [rhost, rport, checkdata]
                if not thisserver in self.serverlist:
                    self.serverlist.append(thisserver)

                    fieldcheck = {}
            for checkitem in checkdata:
                thisitemparts = checkitem.split("=")
                if len(thisitemparts) > 1:
                    fieldname = thisitemparts[0].lower().replace(" ", "")
                    remainingparts = thisitemparts[1:]
                    fieldkeyword = "=".join(x for x in remainingparts)
                    fieldkeyword = fieldkeyword.lower().replace(
                        "\n",
                        "").replace(
                        "\r",
                        "")
                    if not fieldname in fieldcheck:
                        fieldcheck[fieldname] = fieldkeyword
            self.records.append(Record(rhost, rport, checkdata, fieldcheck))

    def getRecords(self):
        return self.records