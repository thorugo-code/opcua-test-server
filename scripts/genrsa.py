import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key_certificate(
    output_dir,
    key_file="private-key.pem",
    cert_file="certificate.der",
    uri="urn:freeopcua:client",
    country="BR",
    state="São Paulo",
    locality="São Paulo",
    organization="Infinite Foundry",
    organizational_unit="3D Digital Plant",
    common_name="infinitefoundry.com",
    key_size=2048,
    validity_days=365 * 10
):
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # 1. Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # 2. Build subject and issuer (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])

    # 3. Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=validity_days))

    # 4. Add extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            data_encipherment=False,
            key_agreement=False,
            content_commitment=False,
            encipher_only=False,
            decipher_only=False,
            crl_sign=False,
        ), critical=True
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(uri)
        ]), critical=False
    )

    # 5. Sign certificate
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256()
    )

    # 6. Write private key (PEM)
    key_path = os.path.join(output_dir, key_file)
    with open(key_path, 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # 7. Write certificate (DER)
    cert_path = os.path.join(output_dir, cert_file)
    with open(cert_path, 'wb') as f:
        f.write(
            certificate.public_bytes(serialization.Encoding.DER)
        )

    return key_path, cert_path


if __name__ == '__main__':
    out_dir = os.path.join(os.path.dirname(__file__), '../assets/certificates/')
    key_path, cert_path = generate_key_certificate(out_dir)
    print(f"Generated key at {key_path} and cert at {cert_path}")
