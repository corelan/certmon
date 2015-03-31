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
            print(self.gen_mail_body())
            self.mailer.sendmail(self.gen_mail_body().split('\n'), mailsubject=self.subject)
            print("\n[+] Sending email ({})".format(self.send_verbose))