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
from mail.mail_config import MailConfig

from cert.record import Record
from cert.certmon_conf import CertmonConf

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

