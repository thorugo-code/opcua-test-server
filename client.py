import asyncio
import logging
import sys
import socket
from pathlib import Path
from cryptography.x509.oid import ExtendedKeyUsageOID

sys.path.insert(0, "..")
from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from asyncua.crypto.truststore import TrustStore
from asyncua import ua


logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

USE_TRUST_STORE = False

cert_idx = 4
cert_base = Path("assets") / "certificates"
cert = Path(cert_base / "certificate.der")
private_key = Path(cert_base / "private-key.pem")


async def task(loop):
    host_name = socket.gethostname()
    client_app_uri = f"urn:{host_name}:foobar:myselfsignedclient"
    url = "opc.tcp://192.168.1.27:4840/"

    await setup_self_signed_certificate(
        private_key,
        cert,
        client_app_uri,
        host_name,
        [ExtendedKeyUsageOID.CLIENT_AUTH],
        {
            "countryName": "CN",
            "stateOrProvinceName": "AState",
            "localityName": "Foo",
            "organizationName": "Bar Ltd",
        },
    )

    client = Client(url=url)
    client.application_uri = client_app_uri
    # client.session_timeout = 30000
    await client.set_security(
        policy=SecurityPolicyBasic256Sha256,
        mode=ua.MessageSecurityMode.SignAndEncrypt,
        certificate=str(cert),
        private_key=str(private_key),
        server_certificate=None,
    )

    # if USE_TRUST_STORE:
    #     trust_store = TrustStore([Path("examples") / "certificates" / "trusted" / "certs"], [])
    #     await trust_store.load()
    #     validator = CertificateValidator(
    #         CertificateValidatorOptions.TRUSTED_VALIDATION | CertificateValidatorOptions.PEER_SERVER, trust_store
    #     )
    # else:
    #     validator = CertificateValidator(
    #         CertificateValidatorOptions.EXT_VALIDATION | CertificateValidatorOptions.PEER_SERVER
    #     )
    # client.certificate_validator = validator

    await client.connect()

    try:
        async with client:
            while True:
                node_id_obj = client.get_node("ns=3;s=\"NN_Valve_On_Off_DB_111BT001XV029\".\"I_bReturnOpened\"")
                print(await node_id_obj.read_data_value())
                await asyncio.sleep(5)
    except ua.UaError as exp:
        _logger.error(exp)


def main():
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(task(loop))
    loop.close()


if __name__ == "__main__":
    main()
