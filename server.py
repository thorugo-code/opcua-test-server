import random
import logging
import asyncio
from asyncua import Server
from asyncua import ua
from asyncua.crypto.permission_rules import SimpleRoleRuleset
from asyncua.server.users import User, UserRole
# from asyncua.crypto.certificate_handler import CertificateHandler
import os


logging.basicConfig(level=logging.INFO)


USERS = {
    "admin": ("admin", UserRole.Admin),
    "user": ("password", UserRole.User),
}


class CustomUserManager:
    def get_user(self, iserver, username=None, password=None, certificate=None):
        if username in USERS and password == USERS[username][0]:
            role = USERS[username][1]
            return User(role=role)

        return None


async def main():

    # server = Server(user_manager=CustomUserManager())     # Enable user authentication
    server = Server()

    await server.init()

    server.set_endpoint("opc.tcp://localhost:4841/")
    server.set_security_policy(
        [
            ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
            ua.SecurityPolicyType.Basic256Sha256_Sign,
            ua.SecurityPolicyType.NoSecurity
        ],
        # permission_ruleset=SimpleRoleRuleset()            # Enable role-based access control for user authentication
    )

    # Setup certificate paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    trust_list_dir = os.path.join(script_dir, "trusted_certs")
    issuer_list_dir = os.path.join(script_dir, "issuer_certs")
    peer_cert_dir = os.path.join(script_dir, "pending_certs")

    os.makedirs(trust_list_dir, exist_ok=True)
    os.makedirs(issuer_list_dir, exist_ok=True)
    os.makedirs(peer_cert_dir, exist_ok=True)

    # # Setup custom certificate validator
    # cert_validator = ManualApprovalCertificateValidator(
    #     app_path=script_dir,
    #     trust_list_path=trust_list_dir,
    #     issuer_list_path=issuer_list_dir,
    #     peer_cert_path=peer_cert_dir
    # )

    await server.set_application_uri("urn:freeopcua:python:server")
    await server.load_certificate("assets/certificates/certificate.der")
    await server.load_private_key("assets/certificates/private-key.pem")

    idx = await server.register_namespace("test.server.com")

    # Create a test object
    my_obj = await server.nodes.objects.add_object(idx, "MyObject")

    # ✅ 1. Writable Variable
    write_var = await my_obj.add_variable(idx, "WritableVar", 0.0)
    await write_var.set_writable()

    # ✅ 2. Bad Status Variable (simulate bad quality)
    bad_var = await my_obj.add_variable(idx, "BadStatusVar", 42.0)
    # We'll simulate a Bad Status by manually writing with a Bad StatusCode
    await bad_var.set_writable()

    # ✅ 3. Read-Only Variable
    read_only_var = await my_obj.add_variable(idx, "ReadOnlyVar", 99.9)
    # Do NOT set writable → implicitly read-only

    # ✅ 4. Variable that only changes every 10s
    slow_var = await my_obj.add_variable(idx, "SlowChangingVar", 5.0)
    await slow_var.set_writable()

    # ✅ 5. Role-based access variable (write for 'admin' only)
    role_var = await my_obj.add_variable(idx, "AuthenticatedOnlyVar", 1.0)
    await role_var.set_writable()

    # ✅ 6. Random float sensor simulator
    random_sensor_var = await my_obj.add_variable(idx, "RandomSensorVar", 0.0)
    await random_sensor_var.set_writable()

    # ✅ 7. Mirror variable (copies value from WritableVar)
    mirror_var = await my_obj.add_variable(idx, "MirrorVar", 0.0)
    await mirror_var.set_writable()

    counter = 0
    async with server:
        while True:
            await asyncio.sleep(1)
            counter += 1

            # WritableVar gets a new value
            await write_var.write_value(await read_only_var.read_value() + counter)

            if counter % 60 == 0:
                # Simulate BadStatusVar by writing a value with Bad StatusCode
                data_val = ua.DataValue(ua.Variant(0, ua.VariantType.Double), ua.StatusCode(ua.StatusCodes.Bad))
                await bad_var.write_value(data_val)

                # SlowChangingVar - update only every 10 seconds
                await slow_var.write_value(await slow_var.read_value() + counter)

            # Random sensor value
            rand_value = round(random.uniform(20.0, 25.0), 2)
            await random_sensor_var.write_value(rand_value)

            # Mirror WritableVar
            val = await write_var.get_value()
            await mirror_var.write_value(val)

            # Role-based update
            # await role_var.write_value(val * 2)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())