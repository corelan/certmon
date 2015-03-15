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


curdate = datetime.datetime.now()
siteurl = "https://github.com/corelan/certmon"


def getNow():
	return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def showSyntax(args):
	print ("")
	print (" Usage: %s [arguments]" % args[0])
	print ("")
	print (" Optional arguments:")
	print ("     -h                   : show help\n")
	print ("     -c <certconfigfile>  : full path to cert config file.")
	print ("                            Defaults to certmon.conf in current folder\n")
	print ("     -s <smtpconfigfile>  : full path to smtp config file.")
	print ("                            Defaults to certmon_smtp.conf in current folder\n")
	print ("     -w <nr>              : Warn of upcoming expiration x number of days in advance (default: 30)\n")
	print ("     -mail                : Test e-mail configuration\n")
	print ("     -v                   : Show verbose information about the certificates")
	print ("")
	return


def showBanner():

	print ("""
                     __                         
  ____  ____________/  |_  _____   ____   ____  
_/ ___\/ __ \_  __ \   __\/     \ /  _ \ /    \ 
\  \__\  ___/|  | \/|  | |  Y Y  (  <_> )   |  \ 
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


def createMsg(x509,targethost,targetport,targetip, expirdate, diff):
	msg = ""
	issuer = x509.get_issuer()
	serial = x509.get_serial_number()
	subject = x509.get_subject()
	version = x509.get_version()

	extratxt = ""
	if diff < 0:
		extratxt = " (%d days ago)" % (diff * -1)
	else:
		extratxt = " (will expire in %d days)" % (diff)

	msg += "Host: %s, Port: %d, IP: %s\n" % (targethost, targetport, targetip)
	msg += "  Subject: %s\n" % subject
	msg += "  Expiration date: %s%s\n" % (expirdate, extratxt)
	msg += "  Issuer: %s\n" % issuer
	msg += "  Version: %s\n" % version
	msg += "  Serial: %s\n" % serial


	return msg


def checkcerts(certconfigfile,mailconfigfile,alertbefore,showverbose):
	serverlist = getServerlist(certconfigfile)

	warnlist = []
	expirlist = []
	changedlist = []

	if len(serverlist) > 0:

		print ("[+] Found %d entries in the cert config file at %s" % (len(serverlist),certconfigfile))

		for targetrecord in serverlist:

			targethost = targetrecord[0]
			targetport = targetrecord[1]
			checkdata = targetrecord[2]

			fieldcheck = {}

			for checkitem in checkdata:
				thisitemparts = checkitem.split("=")
				if len(thisitemparts) > 1:
					fieldname = thisitemparts[0].lower().replace(" ","")
					remainingparts = thisitemparts[1:]
					fieldkeyword = "=".join(x for x in remainingparts)
					fieldkeyword = fieldkeyword.lower().replace("\n","").replace("\r","")
					if not fieldname in fieldcheck:
						fieldcheck[fieldname] = fieldkeyword

			targetips = [socket.gethostbyname(targethost)]

			for thisip in targetips:
				print ("\n[+] Checking %s (%s:%d)" % (thisip,targethost,targetport))
				target = (thisip,targetport)
				try:
					certinfo = ssl.get_server_certificate(target)
					certinfo = certinfo.replace("=-----END","=\n-----END")
					x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certinfo)
					expirdatestr = str(x509.get_notAfter())
					expirdate = datetime.datetime.strptime(expirdatestr.replace("b'","").replace("'",""),"%Y%m%d%H%M%SZ")

					issuer = x509.get_issuer()
					serial = x509.get_serial_number()
					subject = x509.get_subject()
					version = x509.get_version()

					issuerok = True
					serialok = True
					subjectok = True
					versionok = True
					certchanged = False		
					
					delta = expirdate - curdate             
					if delta.days < 0:
						print ("    *** CERTIFICATE HAS EXPIRED ON %s (%d days ago) ***" % (expirdate,(delta.days * -1)))
						thismsg = createMsg(x509,targethost,targetport,thisip,expirdate,delta.days)
						expirlist.append(thismsg)
					else:
						print ("    Cert expiration OK")
						print ("    Note: Certificate will expire on %s (%d days from now)" % (expirdate,delta.days))
						if delta.days < alertbefore:
							print ("    ** Warning: certificate will expire in less than %d days" % alertbefore)
							thismsg = createMsg(x509,targethost,targetport,thisip,expirdate,delta.days)
							warnlist.append(thismsg)

					if len(fieldcheck) > 0:
						for fieldname in fieldcheck:
							if fieldname == "issuer":
								if not fieldcheck[fieldname] in str(issuer).lower():
									issuerok = False
									certchanged = True
							elif fieldname == "subject":
								if not fieldcheck[fieldname] in str(subject).lower():
									subjectok = False
									certchanged = True
							elif fieldname == "version":
								if not fieldcheck[fieldname] in str(version).lower():
									versionok = False
									certchanged = True
							elif fieldname == "serial":
								if not fieldcheck[fieldname] in str(serial).lower():
									serialok = False
									certchanged = True

					if certchanged:
						print ("    *** CERTIFICATE MAY HAVE BEEN CHANGED ***")
						thismsg = createMsg(x509,targethost,targetport,thisip,expirdate,delta.days)
						
						if not subjectok:
							print ("    Subject field contains '%s'" % subject)
							print ("    Expected to contain: '%s'" % fieldcheck["subject"])
							thismsg += "** Subject field does not contain '%s'\n" % fieldcheck["subject"]
						if not issuerok:
							print ("    Issuer field contains '%s'" % issuer)
							print ("    Expected to contain: '%s'" % fieldcheck["issuer"])
							thismsg += "** Issuer field does not contain '%s'\n" % fieldcheck["issuer"]
						if not versionok:
							print ("    Version field contains '%s'" % version)
							print ("    Expected to contain: '%s'" % fieldcheck["version"])
							thismsg += "** Version field does not contain '%s'\n" % fieldcheck["version"]
						if not serialok:
							print ("    Serial field contains '%s'" % serial)
							print ("      Expected to contain: '%s'" % fieldcheck["serial"])
							thismsg += "** Serial field does not contain '%s'\n" % fieldcheck["serial"]
						changedlist.append(thismsg)

					if showverbose:
						print ("    Certificate information:")
						print ("      subject: %s" % subject)
						print ("      issuer: %s" % issuer)
						print ("      version: %s" % version)
						print ("      serial: %s" % serial)
				except:
					print ("    Unable to dump certificate from server")
					print (traceback.format_exc())

		footer = "\n\nThis report has been auto-generated with certmon.py - %s - %s\n " % (siteurl,getNow())
		if len(expirlist) > 0:
			print("\n[+] Sending email (Expired certificates)")
			expirmsg = "Hi,\n\n"
			expirmsg += "The following certificates have expired:\n\n"
			for l in expirlist:
				expirmsg += l
				expirmsg += "-" * 75
				expirmsg += "\n"
			expirmsg += "\n\n"
			expirmsg += footer

			content = expirmsg.split("\n")
			mailhandler = Mailer(mailconfigfile)
			mailhandler.sendmail(content, mailsubject = "Expired Certificates Alert (certmon.py)")


		if len(warnlist) > 0:
			print("\n[+] Sending email (Certificates about to expire)")
			warnmsg = "Hi,\n\n"
			warnmsg += "The following certificates will expire in less than %d days:\n\n" % alertbefore
			for l in warnlist:
				warnmsg += l
				warnmsg += "-" * 75
				warnmsg += "\n"
			warnmsg += "\n\n"
			warnmsg += footer

			content = warnmsg.split("\n")
			mailhandler = Mailer(mailconfigfile)
			mailhandler.sendmail(content, mailsubject = "Upcoming Certificate Expiration Warning (certmon.py)")	


		if len(changedlist) > 0:
			print("\n[+] Sending email (Changed Certificates)")
			changemsg = "Hi,\n\n"
			changemsg += "The following certificates may have been changed:\n\n"
			for l in changedlist:
				changemsg += l
				changemsg += "-" * 75
				changemsg += "\n"
			changemsg += "\n\n"
			changemsg += footer

			content = changemsg.split("\n")
			mailhandler = Mailer(mailconfigfile)
			mailhandler.sendmail(content, mailsubject = "Certificate Change Alert (certmon.py)")	

	return


def getServerlist(certconfigfile):
	serverlist = []
	if os.path.isfile(certconfigfile):
		f = open(certconfigfile,"r")
		content = f.readlines()
		f.close()
		for l in content:
			checkdata = []
			lstripped = l.replace("\n","").replace("\r","").replace("\t","")
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
				if not thisserver in serverlist:
					serverlist.append(thisserver)
	else:
		print("[-] Oops, file %s does not exist" % certconfigfile)
		print("    Desired format:    host:port   (one entry per line)")
	return serverlist

# ----- classes -----
class MailConfig:

	"""
	Class to manage SMTP email config
	"""

	serverinfo = {}

	def __init__(self, filename):
		self.filename = filename
		self.fullpath = os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)

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
				if thisid != "" and len(serverdata) > 0 and not thisid in self.serverinfo:
					self.serverinfo[thisid] = serverdata
				thisid = line[1:-1]
				serverdata = {}
			if not line.startswith("#") and len(line) > 0 and "=" in line:
				lineparts = line.split("=")
				configparam = lineparts[0]
				if len(lineparts) > 1 and len(configparam) > 0 and len(line) > len(configparam):
					configval = line[len(configparam)+1:]
					serverdata[configparam] = configval
		# save the last one too
		if thisid != "" and len(serverdata) > 0 and not thisid in self.serverinfo:
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
		print ("[+] Saved new config file")
		return

	def initConfigFile(self):
		print ("[+] Creating a new config file.")
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
			i_timeout = input('    > Enter mail server timeout (in seconds, default: 300): ')
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
			i_auth = input('    > Does server require authentication? (yes/no, default: no): ')
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
			i_tls = input('    > Does server require/support STARTTLS ? (yes/no, default: no): ')
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
		print ("[+] Config file appears to contain %d mail server definitions" % len(serverconfigs))
		for mailid in serverconfigs:
			thisconfig = serverconfigs[mailid]
			if "server" in thisconfig:
				self.server = thisconfig["server"]
			if "port" in thisconfig:
				self.port = int(thisconfig["port"])
			print ("[+] Checking if %s:%d is reachable" % (self.server, self.port))
			if check_port(self.server, self.port):
				# fill out the rest and terminate the loop
				print ("    Yup, port is open")
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
				print ("    Nope")
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
		#msg['Disposition-Notification-To'] = self.fromaddress
		msg['To'] = self.to
		msg['X-Priority'] = '2'

		if len(logfile) > 0:
			part = MIMEBase('application', "octet-stream")
			part.set_payload(logtext)
			Encoders.encode_base64(part)
			part.add_header('Content-Disposition', 'attachment; filename="certmon.txt"')
			msg.attach(part)
		noerror = False
		thistimeout = 5
		while not noerror:
			try:
				print ("[+] Connecting to %s on port %d" % (self.server, self.port))
				s = smtplib.SMTP(self.server, self.port, 'minicase', self.timeout)
				print ("[+] Connected")
				if self.usetls:
					print ("[+] Issuing STARTTLS")
					s.starttls()
					print ("[+] STARTTLS established")
				if self.requirelogin:
					print ("[+] Authenticating")
					s.login(self.login, self.password)
					print ("[+] Authenticated")
				print ("[+] Sending email")
				s.sendmail(self.to, [self.to], msg.as_string())
				print ("[+] Mail sent, disconnecting")
				s.quit()
				noerror = True
			except smtplib.SMTPServerDisconnected as e:
				print ("     ** ERROR, Server disconnected unexpectedly")
				print ("        This is probably okay")
				noerror = True
			except smtplib.SMTPResponseException as e:
				print ("     ** ERROR Server returned %s : %s" % (str(e.smtp_code), e.smtp_error))
			except smtplib.SMTPSenderRefused as e:
				print ("     ** ERROR Sender refused %s : %s" % (str(e.smtp_code), smtp_error))
			except smtplib.SMTPRecipientsRefused as e:
				print ("     ** ERROR Recipients refused")
			except smtplib.SMTPDataError as e:
				print ("     ** ERROR Server refused to accept the data")
			except smtplib.SMTPConnectError as e:
				print ("     ** ERROR establishing connection to server")
			except smtplib.SMTPHeloError as e:
				print ("     ** ERROR HELO Error")
			except smtplib.SMTPAuthenticationError as e:
				print ("     ** ERROR Authentication")
			except smtplib.SMTPException as e:
				print ("     ** ERROR Sending email")
			except:
				print ("     ** ERROR Unable to send email !")

			if not noerror:
				print ("     I'll try again in %d seconds" % thistimeout)
				time.sleep(thistimeout)
				if thistimeout < 1200:
					thistimeout += 5
		return




if __name__ == "__main__":


	if sys.version_info <(3,0,0):
		sys.stderr.write("You need python v3 or later to run this script\n")
		exit(1)


	mailconfigerror = True
	workingfolder = os.getcwd()
	mailconfigfile = os.path.join(workingfolder,"certmon_smtp.conf")
	certconfigfile = os.path.join(workingfolder,"certmon.conf")

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

	print ("[+] Current date: %s" % getNow())
	print ("[+] Warn about upcoming expirations in less than %d days" % alertbefore)

	# check email config file
	cEmailConfig = MailConfig(mailconfigfile)
	if not cEmailConfig.configFileExists():
		print ("[-] Oops, email config file %s doesn't exist yet" % mailconfigfile)
		cEmailConfig.initConfigFile()
	else:
		print ("[+] Using mail config file %s" % mailconfigfile)
		cEmailConfig.readConfigFile()

	if "mail" in args:
		content = []
		mailhandler = Mailer(mailconfigfile)
		info = ['certmon.py email test']
		mailhandler.sendmail(info, content, 'Email test')
		sys.exit(0)

	checkcerts(certconfigfile, mailconfigfile, alertbefore,showverbose)

	