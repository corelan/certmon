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

import socket
from socket import gethostname
from .cert import Cert
import logging

logger = logging.getLogger(__name__)

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