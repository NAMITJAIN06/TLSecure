from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,  # ✅ Fixed Encoding
        format=serialization.PublicFormat.UncompressedPoint
    )
    return private_key, public_key

def derive_shared_key(private_key, peer_public_bytes):
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_bytes)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"TLS 1.3 Handshake"
    ).derive(shared_secret)
