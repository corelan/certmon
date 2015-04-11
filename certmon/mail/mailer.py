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

from .mail_config import MailConfig

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import socket
from socket import gethostname
import logging

log = logging.getLogger(__name__)

siteurl = "https://github.com/corelan/certmon"

def check_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        return True
    except:
        return False

class Mailer:

    """
    Class to handle email notifications
    """

    def __init__(self, smtpconfigfile):
        self.server = "127.0.0.1"
        self.timeout = 300
        self.port = 25
        self.to = "root@127.0.0.1"
        self.fromaddress = "root@127.0.0.1"
        self.login = ""
        self.password = ""
        self.requirelogin = False
        self.usetls = False

        # read the config file
        cEmailConfig = MailConfig(smtpconfigfile)
        cEmailConfig.readConfigFile()
        serverconfigs = cEmailConfig.serverinfo
        # connect to the first one that is listening
        log.info(
            "Config file appears to contain %d mail server definitions" %
            len(serverconfigs))
        for mailid in serverconfigs:
            thisconfig = serverconfigs[mailid]
            if "server" in thisconfig:
                self.server = thisconfig["server"]
            if "port" in thisconfig:
                self.port = int(thisconfig["port"])
            log.info(
                "Checking if %s:%d is reachable" %
                (self.server, self.port))
            if check_port(self.server, self.port):
                # fill out the rest and terminate the loop
                log.info("Yup, port is open")
                if "timeout" in thisconfig:
                    self.timeout = int(thisconfig["timeout"])
                if "auth" in thisconfig:
                    if thisconfig["auth"] == "yes":
                        self.requirelogin = True
                    else:
                        self.requirelogin = False
                if "user" in thisconfig:
                    self.login = thisconfig["user"]
                if "pass" in thisconfig:
                    self.password = thisconfig["pass"]
                if "tls" in thisconfig:
                    if thisconfig["tls"] == "yes":
                        self.usetls = True
                    else:
                        self.usetls = False
                if "to" in thisconfig:
                    self.to = thisconfig["to"]
                if "from" in thisconfig:
                    self.fromaddress = thisconfig["from"]
                break
            else:
                log.info("    Nope")
        return

    def sendmail(self, info, logfile=[], mailsubject="Certmon Alert"):
        msg = MIMEMultipart()
        bodytext = "\n".join(x for x in info)
        logtext = "\n".join(x for x in logfile)
        mailbody = MIMEText(bodytext, 'plain')
        msg.attach(mailbody)

        msg['Subject'] = '%s - %s' % (gethostname(), mailsubject)
        msg['From'] = self.fromaddress
        # uncomment the next line if you don't want return receipts
        # msg['Disposition-Notification-To'] = self.fromaddress
        msg['To'] = self.to
        msg['X-Priority'] = '2'

        if len(logfile) > 0:
            part = MIMEBase('application', "octet-stream")
            part.set_payload(logtext)
            Encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                'attachment; filename="certmon.txt"')
            msg.attach(part)
        noerror = False
        thistimeout = 5
        while not noerror:
            try:
                log.info(
                    "Connecting to %s on port %d" %
                    (self.server, self.port))
                s = smtplib.SMTP(
                    self.server,
                    self.port,
                    'minicase',
                    self.timeout)
                log.info("Connected")
                if self.usetls:
                    log.info("Issuing STARTTLS")
                    s.starttls()
                    log.info("STARTTLS established")
                if self.requirelogin:
                    log.info("Authenticating")
                    s.login(self.login, self.password)
                    log.info("Authenticated")
                log.info("Sending email")
                s.sendmail(self.to, [self.to], msg.as_string())
                log.info("Mail sent, disconnecting")
                s.quit()
                noerror = True
            except smtplib.SMTPServerDisconnected as e:
                log.error("Server disconnected unexpectedly. This is probably okay")
                noerror = True
            except smtplib.SMTPResponseException as e:
                log.error(
                    "Server returned %s : %s" %
                    (str(
                        e.smtp_code),
                        e.smtp_error))
            except smtplib.SMTPSenderRefused as e:
                log.error(
                    "Sender refused %s : %s" %
                    (str(
                        e.smtp_code),
                        smtp_error))
            except smtplib.SMTPRecipientsRefused as e:
                log.error("Recipients refused", exc_info=True)
            except smtplib.SMTPDataError as e:
                log.error("Server refused to accept the data", exc_info=True)
            except smtplib.SMTPConnectError as e:
                log.error("Error establishing connection to server", exc_info=True)
            except smtplib.SMTPHeloError as e:
                log.error("HELO Error", exc_info=True)
            except smtplib.SMTPAuthenticationError as e:
                log.error("Authentication", exc_info=True)
            except smtplib.SMTPException as e:
                log.error("Sending email", exc_info=True)
            except:
                log.error("Unable to send email !")

            if not noerror:
                log.info("I'll try again in %d seconds" % thistimeout)
                time.sleep(thistimeout)
                if thistimeout < 1200:
                    thistimeout += 5
        return