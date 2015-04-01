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

siteurl = "https://github.com/corelan/certmon"

import datetime
import logging

log = logging.getLogger(__name__)

def getNow():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class MailList:

    def __init__(self, mailer=None):
        self.cert_msgs = []
        self.footer = "\n\nThis report has been auto-generated with certmon.py - %s - %s\n " % (siteurl, getNow())
        self.body_header = "Hi,\n\n"
        self.body_header += "The following certificates may have been Xed:\n\n"
        self.subject="[certmon.py] mail list subject"
        self.send_verbose = ""
        self.mailer = mailer

    def gen_mail_body(self):
        mail_body = self.body_header
        for cert_msg in self.cert_msgs:
            mail_body += cert_msg
            mail_body += "-" * 75
            mail_body += "\n" 
        mail_body += "\n\n"
        mail_body += self.footer

        return mail_body

    def send(self):
        # NOTE should this be mail content be a method?
        if len(self.cert_msgs) > 0:
            #print(self.gen_mail_body())
            self.mailer.sendmail(self.gen_mail_body().split('\n'), mailsubject=self.subject)