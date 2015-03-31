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
        print(
            "[+] Config file appears to contain %d mail server definitions" %
            len(serverconfigs))
        for mailid in serverconfigs:
            thisconfig = serverconfigs[mailid]
            if "server" in thisconfig:
                self.server = thisconfig["server"]
            if "port" in thisconfig:
                self.port = int(thisconfig["port"])
            print(
                "[+] Checking if %s:%d is reachable" %
                (self.server, self.port))
            if check_port(self.server, self.port):
                # fill out the rest and terminate the loop
                print("    Yup, port is open")
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
                print("    Nope")
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
                print(
                    "[+] Connecting to %s on port %d" %
                    (self.server, self.port))
                s = smtplib.SMTP(
                    self.server,
                    self.port,
                    'minicase',
                    self.timeout)
                print("[+] Connected")
                if self.usetls:
                    print("[+] Issuing STARTTLS")
                    s.starttls()
                    print("[+] STARTTLS established")
                if self.requirelogin:
                    print("[+] Authenticating")
                    s.login(self.login, self.password)
                    print("[+] Authenticated")
                print("[+] Sending email")
                s.sendmail(self.to, [self.to], msg.as_string())
                print("[+] Mail sent, disconnecting")
                s.quit()
                noerror = True
            except smtplib.SMTPServerDisconnected as e:
                print("     ** ERROR, Server disconnected unexpectedly")
                print("        This is probably okay")
                noerror = True
            except smtplib.SMTPResponseException as e:
                print(
                    "     ** ERROR Server returned %s : %s" %
                    (str(
                        e.smtp_code),
                        e.smtp_error))
            except smtplib.SMTPSenderRefused as e:
                print(
                    "     ** ERROR Sender refused %s : %s" %
                    (str(
                        e.smtp_code),
                        smtp_error))
            except smtplib.SMTPRecipientsRefused as e:
                print("     ** ERROR Recipients refused")
                print(e)
            except smtplib.SMTPDataError as e:
                print("     ** ERROR Server refused to accept the data")
                print(e)
            except smtplib.SMTPConnectError as e:
                print("     ** ERROR establishing connection to server")
                print(e)
            except smtplib.SMTPHeloError as e:
                print("     ** ERROR HELO Error")
                print(e)
            except smtplib.SMTPAuthenticationError as e:
                print("     ** ERROR Authentication")
                print(e)
            except smtplib.SMTPException as e:
                print("     ** ERROR Sending email")
                print(e)
            except:
                print("     ** ERROR Unable to send email !")

            if not noerror:
                print("     I'll try again in %d seconds" % thistimeout)
                time.sleep(thistimeout)
                if thistimeout < 1200:
                    thistimeout += 5
        return