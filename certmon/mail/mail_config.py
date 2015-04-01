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

import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MailConfig:

    """
    Class to manage SMTP email config
    """

    serverinfo = {}

    def __init__(self, filename):
        self.filename = filename
        self.fullpath = filename

    def configFileExists(self):
        return os.path.isfile(self.fullpath)

    def readConfigFile(self):
        f = open(self.fullpath, "r")
        content = f.readlines()
        f.close()
        serverdata = {}
        thisid = ""
        for l in content:
            line = l.replace("\n", "").replace("\r", "")
            if line.startswith("[") and line.endswith("]"):
                # new config
                # if we already have a config, save it first
                if thisid != "" and len(
                        serverdata) > 0 and not thisid in self.serverinfo:
                    self.serverinfo[thisid] = serverdata
                thisid = line[1:-1]
                serverdata = {}
            if not line.startswith("#") and len(line) > 0 and "=" in line:
                lineparts = line.split("=")
                configparam = lineparts[0]
                if len(lineparts) > 1 and len(
                        configparam) > 0 and len(line) > len(configparam):
                    configval = line[len(configparam) + 1:]
                    serverdata[configparam] = configval
        # save the last one too
        if thisid != "" and len(
                serverdata) > 0 and not thisid in self.serverinfo:
            self.serverinfo[thisid] = serverdata

        return

    def writeConfigFile(self):
        filecontent = []
        for configid in self.serverinfo:
            thisdata = self.serverinfo[configid]
            filecontent.append("[%s]" % str(configid))
            filecontent += thisdata

        f = open(self.fullpath, "wb")
        for l in filecontent:
            f.write(bytes("%s\n" % l, 'UTF-8'))
        f.close()
        logger.info(" Saved new config file.")
        return

    def initConfigFile(self):
        logger.info(" Creating a new config file.")
        i_server = ""
        i_port = 25
        i_timeout = 300
        i_auth = "no"
        i_user = ""
        i_pass = ""
        i_from = ""
        i_to = ""
        i_tls = "no"

        while True:
            i_server = input('    > Enter smtp mail server IP or hostname: ')
            if not i_server == "":
                break

        while True:
            i_port = input('    > Enter mail server port (default: 25): ')
            if not str(i_port) == "":
                try:
                    i_port = int(i_port)
                    break
                except:
                    continue
            else:
                i_port = 25
                break

        while True:
            i_from = input("    > Enter 'From' email address: ")
            if not i_from == "":
                break

        while True:
            i_to = input("    > Enter 'To' email address: ")
            if not i_to == "":
                break

        while True:
            i_timeout = input(
                '    > Enter mail server timeout (in seconds, default: 300): ')
            if not str(i_timeout) == "":
                try:
                    i_timeout = int(i_timeout)
                    break
                except:
                    continue
            else:
                i_timeout = 300
                break

        while True:
            i_auth = input(
                '    > Does server require authentication? (yes/no, default: no): ')
            i_auth = i_auth.lower()
            if i_auth == "":
                i_auth = "no"
            if i_auth in ["yes", "no"]:
                break

        if i_auth == "yes":
            while True:
                i_user = input('    > Username: ')
                if not i_user == "":
                    break
            while True:
                i_pass = input('    > Password: ')
                if not i_pass == "":
                    break

        while True:
            i_tls = input(
                '    > Does server require/support STARTTLS ? (yes/no, default: no): ')
            i_tls = i_tls.lower()
            if i_tls == "":
                i_tls = "no"
            if i_tls in ["yes", "no"]:
                break

        initserverdata = []
        initserverdata.append("server=%s" % i_server)
        initserverdata.append("port=%d" % i_port)
        initserverdata.append("from=%s" % i_from)
        initserverdata.append("to=%s" % i_to)
        initserverdata.append("timeout=%d" % i_timeout)
        initserverdata.append("auth=%s" % i_auth)
        initserverdata.append("user=%s" % i_user)
        initserverdata.append("pass=%s" % i_pass)
        initserverdata.append("tls=%s" % i_tls)

        self.serverinfo = {}
        self.serverinfo[i_server] = initserverdata
        self.writeConfigFile()
        return