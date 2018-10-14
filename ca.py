from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import uuid

def generateCertAndKeys(): 
    one_day = datetime.timedelta(1, 0, 0)

    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )

    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'Paris Encrypt Test CA'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'My IT Security Company'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Pyencrypt Unit'),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Baltimore')
    ]))
    builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'Paris Encrypt Test CA'),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime(2028, 10, 11))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True,)

    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(),backend=default_backend())
    print(isinstance(certificate, x509.Certificate))
    filename = "ca.crt"
    with open("ca.key", "wb") as f:
        f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        ))

    with open(filename, "wb") as f:
        f.write(certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
        ))

    return filename, public_key, private_key, certificate

def validateCert(certificate):
    with open(certificate, 'r') as f:
        data = f.read()
        cert = x509.load_pem_x509_certificate(data, default_backend())
        if isinstance(cert, x509.Certificate) == True:
            print("Certificate has been validated")
            return cert.public_key()
        else:
            return "Goodbye"