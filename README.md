certmon
=======

certmon.py is a simple certificate expiration monitor script.  It will connect to a given server on a given port, dump the certificate, and check if the certificate has expired or not. 

Additionally, it will also report if a certificate is about to expire in x nr of days.  (Default: 30 days).

On top of that, you can check the contents of certain fields in the certificate & see if it contains a keyword that should be there (to see if the certificate has been changed).

Reports will be sent via email, allowing you to schedule the script to run on regular intervals.

This script requires Python v3 and has been written/tested on Windows 7.
(Unless you know how to fix OpenSSL on Mac/Linux, please run this script on Windows only, with administrator privileges)


Installation instructions (Windows 7)
-------------------------------------

This script requires Python v3 and some libraries. It has been developed and tested using Python v3.4.3, on Windows 7 SP1, 64bit.
Most of the required libraries are installed by default,  but others require manual installation.
(pyOpenSSL, docopt, PySocks) 

Download Python3 from https://www.python.org/downloads and launch the installation package with Administrator privileges.
Perform a default install 'for all users', install in the default installation folder.

Next, open an Administrator command prompt and run the following commands to install the missing libraries:

**PyOpenSSL:**

```
c:
cd\python34
cd scripts
pip install pyOpenSSL
```
(Make sure the machine has direct access to the internet before running the 'pip' command)

If all goes well, you should see something like this:
```
Collecting pyOpenSSL
  Downloading pyOpenSSL-0.14.tar.gz (128kB)
    100% |################################| 131kB 1.4MB/s
Collecting cryptography>=0.2.1 (from pyOpenSSL)
  Downloading cryptography-0.8-cp34-none-win32.whl (960kB)
    100% |################################| 962kB 391kB/s
Collecting six>=1.5.2 (from pyOpenSSL)
  Downloading six-1.9.0-py2.py3-none-any.whl
Collecting pyasn1 (from cryptography>=0.2.1->pyOpenSSL)
  Downloading pyasn1-0.1.7.tar.gz (68kB)
    100% |################################| 69kB 723kB/s
Requirement already satisfied (use --upgrade to upgrade): setuptools in c:\python34\lib\site-packages (from cryptography
>=0.2.1->pyOpenSSL)
Collecting cffi>=0.8 (from cryptography>=0.2.1->pyOpenSSL)
  Downloading cffi-0.9.2-cp34-none-win32.whl (82kB)
    100% |################################| 86kB 1.6MB/s
Collecting pycparser (from cffi>=0.8->cryptography>=0.2.1->pyOpenSSL)
  Downloading pycparser-2.10.tar.gz (206kB)
    100% |################################| 208kB 975kB/s
Installing collected packages: pycparser, cffi, pyasn1, six, cryptography, pyOpenSSL
  Running setup.py install for pycparser

  Running setup.py install for pyasn1


  Running setup.py install for pyOpenSSL
Successfully installed cffi-0.9.2 cryptography-0.8 pyOpenSSL-0.14 pyasn1-0.1.7 pycparser-2.10 six-1.9.0
```

**PySocks:**

```
pip install PySocks
```
Output:
```
Collecting PySocks
  Downloading PySocks-1.5.3.tar.gz
Installing collected packages: PySocks
  Running setup.py install for PySocks
Successfully installed PySocks-1.5.3
```

**docopt:**

```
pip install docopt
```
Output
```
Collecting docopt
  Downloading docopt-0.6.2.tar.gz
Installing collected packages: docopt
  Running setup.py install for docopt
Successfully installed docopt-0.6.2
```


Finally, download the certmon script zip file: https://github.com/corelan/certmon/archive/master.zip and extract it to a folder (e.g. c:\certmon)
(or simply clone the repository via git to a local folder)


Syntax
------

```
C:\certmon>c:\python34\python.exe certmon.py -h

                     __
  ____  ____________/  |_  _____   ____   ____
_/ ___\/ __ \_  __ \   __\/     \ /  _ \ /    \
\  \__\  ___/|  | \/|  | |  Y Y  (  <_> )   |  \
 \___  >___  >__|   |__| |__|_|  /\____/|___|  /
     \/    \/                  \/            \/

              corelanc0d3r - www.corelan.be
              https://github.com/corelan/certmon

certmon - Monitor TLS Certificates

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

(The fields must be ; separated, and the first field must contain the hostname and port).

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


limitations / known issues
--------------------------
The script is not able to handle host headers or URI's.  It will simply connect to a server on a port, and dump the certificate.  


License
-------
GPL

