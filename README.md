certmon
=======

certmon.py is a simple certificate expiration monitor script.  It will connect to a given server on a given port, dump the certificate, and check if the certificate has expired or not. Additionally, it will also report if a certificate is about to expire in x nr of days.  (Default: 30 days)
On top of that, you can check the contents of certain fields in the certificate & see if it contains a keyword that should be there (to see if the certificate has been changed).

Reports will be sent via email, allowing you to schedule the script to run on regular intervals.

This script requires Python v3 and has been written/tested on Windows 7.
(Unless you know how to fix OpenSSL on Mac/Linux, please run this script on Windows only, with administrator privileges)


Installation instructions (Windows 7)
-------------------------------------

This script requires Python v3 and the pyOpenSSL library.   It has been developed and tested using Python v3.4.3, on Windows 7 SP1, 64bit.

Download Python3 from https://www.python.org/downloads and launch the installation package with Administrator privileges.
Perform a default install 'for all users', install in the default installation folder.

Next, open an Administrator command prompt and run the following commands to install pyOpenSSL:

```
c:
cd\python34
cd scripts
pip install pyOpenSSL
```
(Make sure the machine has direct access to the internet.)



Syntax
------

```
C:\>c:\python34\python.exe certmon.py -h

                     __
  ____  ____________/  |_  _____   ____   ____
_/ ___\/ __ \_  __ \   __\/     \ /  _ \ /    \
\  \__\  ___/|  | \/|  | |  Y Y  (  <_> )   |  \
 \___  >___  >__|   |__| |__|_|  /\____/|___|  /
     \/    \/                  \/            \/

              corelanc0d3r - www.corelan.be
              https://github.com/corelan/certmon


 Usage: certmon.py [arguments]

 Optional arguments:
     -h                   : show help

     -c <certconfigfile>  : full path to cert config file.
                            Defaults to certmon.conf in current folder

     -s <smtpconfigfile>  : full path to smtp config file.
                            Defaults to certmon_smtp.conf in current folder

     -w <nr>              : Warn of upcoming expiration x number of days in advance (default: 30)

     -mail                : Test e-mail configuration

     -v                   : Show verbose information about the certificates
```


Usage
-----

The script takes 2 input files, which are expected to be placed in the current folder.
(You can specify an alternate location using parameters -c and -s)

`certmon.conf`

This is where you can specify the hostnames & ports to connect to.

`certmon_smtp.conf` 

This file contains information about your SMTP server, and the email addresses to use.

You can tweak the warning threshold with parameter -w.


certmon.conf syntax
-------------------

This file contains the hostnames and portnumbers (default 443) to connect to.
Syntax:
```
hostname:port
```
(only specify one hostname:port combination per line)

If you want certmon to also monitor the certificate itself, you can specify which keywords it should contain in certain fields. Supported fields are:

```
subject
issuer
version
serial
```

Example:  Let's say I want to monitor the certificate on www.corelan.be, and I want to be sure that the subject field contains 'www.corelan.be', the issuer field contains the keyword 'StartCom', and the serial number field contains '1056083', then the line inside the certmon.conf file should look like this:

```
www.corelan.be:443;issuer=StartCom;serial=1056083;subject=www.corelan.be
```

This configuration will trigger the following behaviour:

If the certificate on www.corelan.be (port 443) will expire in 30 days or less, you will get an email warning.

If the certificate on www.corelan.be (port 443) has expired, you will get an email alert.

If one of the 3 fields doesn't contain the corresponding keywords, you will get an email alert.


(Hint: If you want to know what exactly is inside the various fields, simply use option -v)

Note: The field compliance check will be performed against a lowercase conversion of the field & the keyword.


certmon_smtp.conf syntax
------------------------

This is easy.  If the script is unable to find the smtp configuration file, it will ask you a couple of questions & create the file for you.
If you want to check if the mail configuration works correctly simply run the script with option -mail.
You should get a test email in your mailbox.



