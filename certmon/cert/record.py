import socket
from socket import gethostname

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