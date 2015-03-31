#!/usr/bin/env python3

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
import sys
import ssl
import socket
from socket import gethostname
import OpenSSL
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import traceback
import time

from mail.mail_list import MailList
from mail.mailer import Mailer

curdate = datetime.datetime.now()
siteurl = "https://github.com/corelan/certmon"

def check_python_version():
    if sys.version_info < (3, 0, 0):
        sys.stderr.write("You need python v3 or later to run this script\n")
        exit(1)

def getNow():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def showSyntax(args):
    print("")
    print(" Usage: %s [arguments]" % args[0])
    print("")
    print(" Optional arguments:")
    print("     -h                   : show help\n")
    print("     -c <certconfigfile>  : full path to cert config file.")
    print("                            Defaults to certmon.conf in current folder\n")
    print("     -s <smtpconfigfile>  : full path to smtp config file.")
    print("                            Defaults to certmon_smtp.conf in current folder\n")
    print("     -w <nr>              : Warn of upcoming expiration x number of days in advance (default: 30)\n")
    print("     -mail                : Test e-mail configuration\n")
    print("     -v                   : Show verbose information about the certificates")
    print("")
    return


def showBanner():

    print ("""
                     __
  ____  ____________/  |_  _____   ____   ____
_/ ___\/ __ \_  __ \   __\/     \ /  _ \ /    \\
\  \__\  ___/|  | \/|  | |  Y Y  (  <_> )   |  \\
 \___  >___  >__|   |__| |__|_|  /\____/|___|  /
     \/    \/                  \/            \/

              corelanc0d3r - www.corelan.be
              %s
  """ % siteurl)

    return


def check_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        return True
    except:
        return False


# ----- classes -----

class Record:

    def __init__(self, rhost, rport, checkdata, fieldcheck):
        self.fields_to_check = {}
        self.host = rhost
        self.port = rport
        self.checkdata = checkdata
        self.fieldcheck = fieldcheck
        self.IPs = None

        self._get_IPs()

    def _get_IPs(self):
        # Note this needs null error validation and try,except block
        self.IPs = [socket.gethostbyname(self.host)]

    def fetch_certs(self):
        certs = []
        for ip in self.IPs:
            certs.append(Cert(ip=ip, port=self.port, fieldcheck=self.fieldcheck))
        return certs




def init_changed_mail_list(mailer=None):
    changed_list = MailList(mailer)
    changed_list.body_header = "Hi,\n\n"
    changed_list.body_header += "The following certificates may have been changed:\n\n"
    changed_list.subject="Certificate Change Alert (certmon.py)"
    return changed_list


def init_warn_mail_list(mailer=None):
    warn_list = MailList(mailer)
    warn_list.body_header = "Hi,\n\n"
    warn_list.body_header += "The following certificates will expire in less than %d days:\n\n" % alertbefore
    warn_list.subject="Upcoming Certificate Expiration Warning (certmon.py)"
    return warn_list


def init_expired_mail_list(mailer=None):
    expired_list = MailList(mailer)
    expired_list.body_header = "Hi,\n\n"
    expired_list.body_header += "The following certificates have expired:\n\n"
    expired_list.subject="Expired Certificates Alert (certmon.py)"
    return expired_list


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


class MailConfig:

    """
    Class to manage SMTP email config
    """

    serverinfo = {}

    def __init__(self, filename):
        self.filename = filename
        self.fullpath = os.path.join(
            os.path.dirname(
                os.path.realpath(__file__)),
            filename)

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
        print("[+] Saved new config file")
        return

    def initConfigFile(self):
        print("[+] Creating a new config file.")
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


if __name__ == "__main__":

    check_python_version()

    mailconfigerror = True
    workingfolder = os.getcwd()
    mailconfigfile = os.path.join(workingfolder, "certmon_smtp.conf")
    certconfigfile = os.path.join(workingfolder, "certmon.conf")

    showBanner()
    alertbefore = 30
    showverbose = False

    arguments = []
    if len(sys.argv) >= 2:
        arguments = sys.argv[1:]

    args = {}
    last = ""
    for word in arguments:
        if (word[0] == '-'):
            word = word.lstrip("-")
            args[word] = True
            last = word
        else:
            if (last != ""):
                if str(args[last]) == "True":
                    args[last] = word
                else:
                    args[last] = args[last] + " " + word

    if "h" in args:
        showSyntax(sys.argv)
        sys.exit(0)

    if "c" in args:
        if type(args["c"]).__name__.lower() != "bool":
            certconfigfile = args["c"]

    if "s" in args:
        if type(args["s"]).__name__.lower() != "bool":
            mailconfigfile = args["s"]

    if "w" in args:
        if type(args["w"]).__name__.lower() != "bool":
            try:
                alertbefore = int(args["w"])
            except:
                pass

    if "v" in args:
        showverbose = True

    print("[+] Current date: %s" % getNow())
    print(
        "[+] Warn about upcoming expirations in less than %d days" %
        alertbefore)

    # check email config file
    cEmailConfig = MailConfig(mailconfigfile)
    if not cEmailConfig.configFileExists():
        print(
            "[-] Oops, email config file %s doesn't exist yet" %
            mailconfigfile)
        cEmailConfig.initConfigFile()
    else:
        print("[+] Using mail config file %s" % mailconfigfile)
        cEmailConfig.readConfigFile()

    if "mail" in args:
        content = []
        mailhandler = Mailer(mailconfigfile)
        info = ['certmon.py email test']
        mailhandler.sendmail(info, content, 'Email test')
        sys.exit(0)

    mailhandler = Mailer(mailconfigfile)
    warn_list = init_warn_mail_list(mailer=mailhandler)
    expired_list = init_expired_mail_list(mailer=mailhandler)
    changed_list = init_changed_mail_list(mailer=mailhandler)

    all_certs = []
    certmon_conf = CertmonConf(certconfigfile)
    for record in certmon_conf.records:
        all_certs += record.fetch_certs()

    for cert in all_certs:
        if cert.is_expired():
            expired_list.cert_msgs.append(cert.msg())
        if cert.is_alertbefore():
            warn_list.cert_msgs.append(cert.msg())
        if cert.is_changed():
            changed_list.cert_msgs.append(cert.msg())

    expired_list.send()
    warn_list.send()
    changed_list.send()

