import socket
import ssl
import sys
import urllib.parse
import OpenSSL
from Crypto.Util import asn1
from dateutil import parser


def CertInfo(url, port=443):
    host = urllib.parse.urlparse(url).netloc
    try:
        # cert = ssl.get_server_certificate((host, port))
        conn = socket.create_connection((host, port))
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sock = context.wrap_socket(conn, server_hostname=host)
        cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
    except Exception as e:
        return ''
    if not cert:
        return ''
    result = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert.encode())
    """证书版本"""
    Version = result.get_version()
    Serial_Number = int_to_hex(hex(result.get_serial_number()).replace('0x', ''))

    """证书中使用的签名算法"""
    Signature_Algorithm = result.get_signature_algorithm().decode() \
        .replace('With', '-').replace('Encryption', '').upper()

    """颁发者"""
    Issuer = ''
    Issuer_tmp = result.get_issuer().get_components()
    for i in Issuer_tmp:
        if '' != Issuer:
            Issuer = ', '.join((Issuer, f'{i[0].decode()}={i[1].decode()}'))
        else:
            Issuer = f'{i[0].decode()}={i[1].decode()}'

    """有效期从 到 """
    Not_Before = str(parser.parse(result.get_notBefore().decode()).strftime('%Y-%m-%d %H:%M:%S')) + " UTC"
    Not_After = str(parser.parse(result.get_notAfter().decode()).strftime('%Y-%m-%d %H:%M:%S')) + " UTC"

    Subject_tmp = result.get_subject().get_components()
    Subject = ''
    for i in Subject_tmp:
        if '' != Subject:
            Subject = ', '.join((Subject, f'{i[0].decode()}={i[1].decode()}'))
        else:
            Subject = f'{i[0].decode()}={i[1].decode()}'

    Public_Key_Algorithm = Signature_Algorithm.split('-')[1]
    """公钥长度"""
    Public_Key_Bits = result.get_pubkey().bits()

    """公钥"""
    Public_Key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, result.get_pubkey()).decode("utf-8").replace('\n', '')

    """Public Modulus"""
    private_key_der = asn1.DerSequence()
    private_key_der.decode(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, result.get_pubkey()))
    Modulus = int_to_hex(hex(private_key_der[1]).replace('0x', ''))
    Exponent = private_key_der[2]
    """extensions"""
    X509v3_extensions = ''
    for i in range(result.get_extension_count()):
        X509v3_extensions = ' '.join(
            (X509v3_extensions, str(result.get_extension(i)).strip())) if '' != X509v3_extensions else str(
            result.get_extension(i)).strip()

    X509v3_extensions = X509v3_extensions.replace('\n', ' ')

    """指纹"""
    Fingerprint_MD5 = result.digest('md5').decode()
    Fingerprint_SHA1 = result.digest('sha1').decode()
    Fingerprint_SHA_256 = result.digest('sha256').decode()
    """签名"""
    Sign = int_to_hex(result.to_cryptography().signature.hex())
    # data = {
    #     'Version': Version,
    #     'Serial_Number': Serial_Number,
    #     'Signature_Algorithm': Signature_Algorithm,
    #     'Issuer': Issuer,
    #     'Not_Before': Not_Before,
    #     'Not_After': Not_After,
    #     'Subject': Subject,
    #     'Public_Key_Algorithm': Public_Key_Algorithm,
    #     'Public_Key_Bits': Public_Key_Bits,
    #     'Public_Key': Public_Key,
    #     'Modulus': Modulus,
    #     'Exponent': Exponent,
    #     'X509v3_extensions': X509v3_extensions,
    #     'Sign': Sign,
    #     'Fingerprint_MD5': Fingerprint_MD5,
    #     'Fingerprint_SHA1': Fingerprint_SHA1,
    #     'Fingerprint_SHA_256': Fingerprint_SHA_256,
    #  }
    Certificate = f"""
Certificate:
    Data:
        Version: {Version+1} (0x{Version})
        Serial Number:
            {Serial_Number}
    Signature Algorithm: {Signature_Algorithm}
        Issuer: {Issuer}
        Validity
            Not Before: {Not_Before}
            Not After : {Not_After}
        Subject: {Subject}
        Subject Public Key Info:
            Public Key Algorithm: {Public_Key_Algorithm}
                Public-Key-Bits: ({Public_Key_Bits} bit)
                Public-Key: {Public_Key}
                Modulus:
                    {Modulus}
                Exponent: {Exponent} (0x{hex(Exponent)})
        X509v3 extensions:
            {X509v3_extensions}

    Signature Algorithm: {Signature_Algorithm}
         {Sign}

Thumbprint MD5: {Fingerprint_MD5}
Thumbprint SHA1: {Fingerprint_SHA1}
Thumbprint SHA256: {Fingerprint_SHA_256}
    """
    return Certificate


def int_to_hex(data):
    serial = ':'.join([data[i:i + 2] for i in range(0, len(data), 2)])
    return serial


if __name__ == '__main__':
    url = 'https://www.ln55.com/'
    issuedDic = CertInfo(url)
    print(issuedDic)
