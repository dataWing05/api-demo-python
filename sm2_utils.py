import base64
from gmssl import sm2
from asn1crypto import pem, keys

# Load SM2 public key from PEM file
def load_public_key_from_pem(pem_file_path):
    try:
        with open(pem_file_path, 'rb') as f:
            pem_data = f.read()
        res= pem.unarmor(pem_data)
        der_bytes, pem_type = res[2], res[0]
        if pem_type != 'PUBLIC KEY':
            raise ValueError("PEM file is not a PUBLIC KEY")
        public_key_info = keys.PublicKeyInfo.load(der_bytes)
        if public_key_info.algorithm != 'ec':
            raise ValueError("Not an SM2 public key (expected sm2p256v1 curve)")
        public_key_bytes = public_key_info['public_key'].native
        public_key_hex = public_key_bytes.hex()
        return public_key_hex
    except Exception as e:
        raise ValueError(f"Failed to parse public key: {str(e)}")

def encrypt_sm2(data):
    public_key_hex = load_public_key_from_pem("public_key.pem")
    sm2_crypt = sm2.CryptSM2(public_key=public_key_hex, private_key=None, mode=1)
    print(sm2_crypt.mode)
    encrypted_raw = sm2_crypt.encrypt(data.encode('utf-8'))

    c1_len = 64  # gmssl C1: 64 bytes (x+y)
    c3_len = 32
    c2_start = c1_len
    if sm2_crypt.mode == 1:  # C1C3C2
        c3_start = c1_len
        c2_start = c1_len + c3_len
    else:  # C1C2C3 (default)
        c3_start = -c3_len

    c1 = encrypted_raw[:c1_len]
    c2 = encrypted_raw[c2_start:-c3_len if sm2_crypt.mode == 0 else c2_start + len(encrypted_raw[c2_start:])]
    c3 = encrypted_raw[c3_start:c3_start + c3_len]

    # fix C1 to include '04' prefix
    c1_fixed = b'\x04' + c1

    # reconstruct encrypted data with fixed C1
    if sm2_crypt.mode == 1:  # C1C3C2
        encrypted_fixed = c1_fixed + c3 + c2
    else:  # C1C2C3
        encrypted_fixed = c1_fixed + c2 + c3
    encrypted_b64 = base64.b64encode(encrypted_fixed).decode('utf-8')
    print("Fixed Encrypted (Base64):", encrypted_b64)
    print("Fixed C1 hex (first bytes):", c1_fixed[:10].hex())  # should start with '04'
    return encrypted_b64
