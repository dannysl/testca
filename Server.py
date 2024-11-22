from flask_cors import CORS
from flask import Flask, request
from OpenSSL import crypto

app = Flask(__name__)
pem = {
    "time": "",
    "uefi": "",
    "code": ""
}
CORS(app)


class Server:
    @staticmethod
    def issueCert():
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # 创建一个自签名证书
        cert = crypto.X509()
        cert.get_subject().C = "CN"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "Location"
        cert.get_subject().O = "Organization"
        cert.get_subject().OU = "Organizational Unit"
        cert.get_subject().CN = "Common Name"
        cert.get_subject().D = "Description"
        cert.get_subject().N = "Name"
        cert.set_serial_number(1000)
        cert.set_notBefore(b'20000101000000Z')
        cert.set_notAfter(b'20241231235959Z')
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        with open('certificate.crt', 'w', encoding='utf8') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf - 8'))
        with open('private_key.pem', 'w') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf - 8'))

    @staticmethod
    @app.route('/', methods=['GET'])
    def issuePage():
        ca_name = request.args.get('ca_name')
        va_time = request.args.get('va_time')
        in_data = request.args.get('in_data')
        in_code = request.args.get('in_code')
        in_main = request.args.get('in_main')
        in_subs = request.args.get('in_subs')
        in_orgs = request.args.get('in_orgs')
        in_orgu = request.args.get('in_orgu')


if __name__ == '__main__':
    Server.issueCert()
    # cos = CORS(app, resources={r"/*": {"origins": "*"}})
    # app.run(debug=True,
    #         host='0.0.0.0',
    #         port=1080,
    #         use_reloader=False)