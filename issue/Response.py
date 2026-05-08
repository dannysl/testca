import os.path
import datetime
from OpenSSL import crypto
from oscrypto import asymmetric

from ocsps.response import OCSPResponder, CertificateStatus

url = {
    "Pikachu Code Sub CA": "certs/codeca/0.4-Pikachu_Code_Sub_CA",
    "Pikachu Time Sub CA": "certs/timeca/0.2-Pikachu_Time_Sub_CA",
    "Pikachu UEFI Sub CA": "certs/uefica/0.3-Pikachu_UEFI_Sub_CA",
    "Pikachu Test CA RSA": "certs/rootca/0-Pikachu_Test_CA_RSA"
}


class OCSP:
    @staticmethod
    def getIssue(in_path):
        with open(in_path) as f:
            temp_cer = crypto.load_certificate(
                crypto.FILETYPE_PEM, f.read().encode())
        temp_cer = temp_cer.get_issuer().CN
        if temp_cer in url:
            return (asymmetric.load_certificate(
                url[temp_cer] + ".crt"), asymmetric.load_private_key(
                url[temp_cer] + ".key"))
        return None

    @staticmethod
    def validate(serial: int):
        serial = str(hex(serial))[2:]
        cert_t = "saves/%s.crt" % serial
        cert_r = "saves/%s.crl" % serial
        # 找不到文件 ==================================
        cert_o = "certs/serial/%s.crt" % serial
        if os.path.exists(cert_o):
            cert_t = cert_o
        if not os.path.exists(cert_t):
            return CertificateStatus.unknown, None, None
        issuer = OCSP.getIssue(cert_t)
        # 读取证书 ====================================
        with open(cert_t) as cert_f:
            cert_cer = crypto.load_certificate(
                crypto.FILETYPE_PEM,
                cert_f.read().encode())
        cert_now = cert_cer.get_notAfter()
        cert_str = datetime.datetime.strptime(
            cert_now.decode(), "%Y%m%d%H%M%SZ")
        time_now = datetime.datetime.now()
        # 已经被吊销 ==================================
        if os.path.exists(cert_r):
            return (CertificateStatus.revoked,
                    cert_str, issuer)
        # 未被吊销 ====================================
        else:
            # 已经过期 ================================
            if cert_str < time_now:
                return (CertificateStatus.revoked,
                        cert_str, issuer)
            else:
                return (CertificateStatus.good,
                        cert_str, issuer)

    @staticmethod
    def loadCert(serial: int) -> str:
        serial = str(hex(serial))[2:]
        cer_path = 'saves/%s.crt' % serial
        cer_self = "certs/serial/%s.crt" % serial
        if os.path.exists(cer_self):
            cer_path = cer_self
        if not os.path.exists(cer_path):
            return ""
        with open(cer_path, 'r') as f:
            return f.read().strip()


if __name__ == '__main__':
    app = OCSPResponder(
        # [i + ".crt" for i in url],
        "certs/rootca/0-Pikachu_Test_CA_RSA.crt",
        # [i + ".crt" for i in url],
        # [i + ".key" for i in url],
        "certs/rootca/0-Pikachu_Test_CA_RSA.crt",
        "certs/rootca/0-Pikachu_Test_CA_RSA.key",
        validate_func=OCSP.validate,
        cert_retrieve_func=OCSP.loadCert,
        next_update_days=1
    )
    app.serve(port=1008, debug=True)
