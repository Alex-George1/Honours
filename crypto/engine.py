import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import IV_SIZE, BLOCK_HEADER_SIZE

def encrypt_payload(packaged_blocks: list, key: bytes):
    aesgcm = AESGCM(key)
    final_payload = b""
    for block_bytes in packaged_blocks:
        iv = os.urandom(IV_SIZE)
        ciphertext = aesgcm.encrypt(iv, block_bytes, None)
        size = len(iv) + len(ciphertext)
        final_payload += size.to_bytes(BLOCK_HEADER_SIZE, 'big') + iv + ciphertext
    return final_payload

def decrypt_payload(binary_stream: bytes, key: bytes):
    aesgcm = AESGCM(key)
    decrypted_blocks = []
    offset = 0
    while offset < len(binary_stream):
        if len(binary_stream) - offset < BLOCK_HEADER_SIZE: break
        size = int.from_bytes(binary_stream[offset:offset+BLOCK_HEADER_SIZE], 'big')
        offset += BLOCK_HEADER_SIZE
        chunk = binary_stream[offset:offset+size]
        iv = chunk[:IV_SIZE]
        ciphertext = chunk[IV_SIZE:]
        offset += size
        try:
            decrypted_blocks.append(aesgcm.decrypt(iv, ciphertext, None))
        except:
            decrypted_blocks.append(b'{"error": "AUTH_FAILURE"}')
    return decrypted_blocks