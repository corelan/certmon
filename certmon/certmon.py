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
import datetime
import traceback
import logging
import socks
import socket
import urllib.request

__doc__ = """certmon - Monitor TLS Certificates

Usage:
    certmon.py [-v] [--tor] [-c=<certconfigfile>] [-s=<smtpconfigfile>] [-w=<nr>]
    certmon.py (-h | --help)
    certmon.py --test-mail

Options:
    -h --help               Show this help screen.
    -c=<certconfigfile>     Full path to cert config file [default: certmon.conf].
    -s=<smtpconfigfile>     Full path to smtp config file [default: certmon_smtp.conf].
    -w=<nr>                 Warn of upcoming expiration nr of days in advance [default: 30].
    --test-mail             Test e-mail configuration.
    -v                      Show verbose information about the certificates.
    --tor                   Make certificate requests via default tor socks proxy localhost 9050.

"""
from docopt import docopt

from mail.mail_list import MailList
from mail.mailer import Mailer
from mail.mail_config import MailConfig

from cert.record import Record
from cert.certmon_conf import CertmonConf

log = logging.getLogger(__name__)
curdate = datetime.datetime.now()
siteurl = "https://github.com/corelan/certmon"


def getNow():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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

    arguments = docopt(__doc__, version='0.0.1')

    mailconfigerror = True
    mailconfigfile = arguments['-s']
    certconfigfile = arguments['-c']
    alertbefore = int(arguments['-w'])
    verbose = arguments['-v']

    if verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(format="[+] %(message)s",level=logging.INFO)

    showBanner()

    log.info("Current date: %s", getNow())
    log.info("Warn about upcoming expirations in less than %d days", alertbefore)

    cEmailConfig = MailConfig(mailconfigfile)
    if not cEmailConfig.configFileExists():
        log.warning("Oops, email config file %s doesn't exist yet", mailconfigfile)
        cEmailConfig.initConfigFile()
    else:
        log.info("Using mail config file %s", mailconfigfile)
        cEmailConfig.readConfigFile()

    if arguments['--test-mail']:
        log.info("Test Mail Configuration")
        content = []
        mailhandler = Mailer(mailconfigfile)
        info = ['certmon.py email test']
        mailhandler.sendmail(info, content, 'Email test')
        sys.exit(0)

    mailhandler = Mailer(mailconfigfile)
    warn_list = init_warn_mail_list(mailer=mailhandler)
    expired_list = init_expired_mail_list(mailer=mailhandler)
    changed_list = init_changed_mail_list(mailer=mailhandler)

    if arguments['--tor']:
        original_socket = socket.socket
        socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
        socket.socket = socks.socksocket
        log.info("socks public ip: " + str(urllib.request.urlopen('http://ip.42.pl/raw').read()))

    all_certs = []
    certmon_conf = CertmonConf(certconfigfile)
    for record in certmon_conf.records:
        all_certs += record.fetch_certs()

    log.info("-" * 75)
    for cert in all_certs:
        log.info("")
        log.info("Checking cert on %s (%s), port %s" % (cert.host, cert.ip, cert.port))
        if cert.is_expired():
            expired_list.cert_msgs.append(cert.msg())
        if cert.is_alertbefore():
            warn_list.cert_msgs.append(cert.msg())
        if cert.is_changed():
            changed_list.cert_msgs.append(cert.msg())
    log.info("-" * 75)

    if arguments['--tor']:
        socket.socket = original_socket
        log.info("public ip: " + str(urllib.request.urlopen('http://ip.42.pl/raw').read()))

    expired_list.send()
    warn_list.send()
    changed_list.send()

