from io import BytesIO
import cbor2

from .exceptions import InvalidAuthenticatorDataStructure
from .structs import AttestedCredentialData, AuthenticatorData, AuthenticatorDataFlags


def parse_authenticator_data(val: bytes) -> AuthenticatorData:
    """
    Turn `response.attestationObject.authData` into structured data

    For how this is structured, refer to https://www.w3.org/TR/webauthn/#sctn-attestation
    """
    # Don't bother parsing if there aren't enough bytes for at least:
    # - rpIdHash (32 bytes)
    # - flags (1 byte)
    # - signCount (4 bytes)
    if len(val) < 37:
        raise InvalidAuthenticatorDataStructure(
            f"Authenticator data was {len(val)} bytes, expected at least 37 bytes"
        )

    pointer = 0

    rp_id_hash = val[pointer:32]
    pointer += 32

    # Cast byte to ordinal so we can use bitwise operators on it
    flags_bytes = ord(val[pointer : pointer + 1])
    pointer += 1

    sign_count = val[pointer : pointer + 4]
    pointer += 4

    # Parse flags
    flags = AuthenticatorDataFlags(
        up=flags_bytes & (1 << 0) != 0,
        uv=flags_bytes & (1 << 2) != 0,
        at=flags_bytes & (1 << 6) != 0,
        ed=flags_bytes & (1 << 7) != 0,
    )

    # The value to return
    authenticator_data = AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=int.from_bytes(sign_count, "big"),
    )

    # Parse AttestedCredentialData if present
    if flags.at is True:
        aaguid = val[pointer : pointer + 16]
        pointer += 16

        credential_id_len = int.from_bytes(val[pointer : pointer + 2], "big")
        pointer += 2

        credential_id = val[pointer : pointer + credential_id_len]
        pointer += credential_id_len

        # The next part is the public key (COSE).
        # As there can be extensions behind that and there is no field that tells how long it is,
        # we must decode and re-encode it via CBOR.
        credential_public_key_and_extensions = val[pointer:]
        credential_public_key = None
        extensions = None
        with BytesIO(credential_public_key_and_extensions) as fp:
            decoder = cbor2.CBORDecoder(fp)
            credential_public_key = cbor2.dumps(decoder.decode())
            try:
                # When bytes are left, those are the extensions
                extensions = cbor2.dumps(decoder.decode())
            except cbor2.CBORDecodeEOF:
                pass

        attested_cred_data = AttestedCredentialData(
            aaguid=aaguid,
            credential_id=credential_id,
            credential_public_key=credential_public_key,
        )
        authenticator_data.attested_credential_data = attested_cred_data
        authenticator_data.extensions = extensions

    return authenticator_data
