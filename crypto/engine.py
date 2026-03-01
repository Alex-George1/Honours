import os
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import IV_SIZE, BLOCK_HEADER_SIZE

def encrypt_payload(packaged_blocks: list, key: bytes):
    aesgcm = AESGCM(key)
    final_payload = b""
    for idx, block_bytes in enumerate(packaged_blocks):
        iv = os.urandom(IV_SIZE)
        ciphertext = aesgcm.encrypt(iv, block_bytes, None)
        size = len(iv) + len(ciphertext)
        size_header = size.to_bytes(BLOCK_HEADER_SIZE, 'big')
        final_payload += size_header + iv + ciphertext
        print(f"\n   [BLOCK {idx + 1} - BEFORE ENCRYPTION]")
        print(f"   - Plaintext (JSON): {block_bytes.decode('utf-8')}")
        print(f"   - Plaintext Size: {len(block_bytes)} bytes")
        
        # Debug output AFTER encryption
        print(f"\n   [BLOCK {idx + 1} - AFTER ENCRYPTION]")
        print(f"   - Size Header (4 bytes, big-endian): {binascii.hexlify(size_header).decode()}")
        print(f"   - IV (12 bytes): {binascii.hexlify(iv).decode()}")
        print(f"   - Ciphertext ({len(ciphertext)} bytes): {binascii.hexlify(ciphertext[:32]).decode()}...")
        print(f"   - Total Block Size (header + IV + ciphertext): {4 + len(iv) + len(ciphertext)} bytes")
    return final_payload

def decrypt_payload(binary_stream: bytes, key: bytes):
    aesgcm = AESGCM(key)
    decrypted_blocks = []
    offset = 0
    block_num = 0
    while offset < len(binary_stream):
        if len(binary_stream) - offset < BLOCK_HEADER_SIZE: break
        block_num += 1
        size = int.from_bytes(binary_stream[offset:offset+BLOCK_HEADER_SIZE], 'big')
        size_header = binary_stream[offset:offset+BLOCK_HEADER_SIZE]
        offset += BLOCK_HEADER_SIZE
        chunk = binary_stream[offset:offset+size]
        iv = chunk[:IV_SIZE]
        ciphertext = chunk[IV_SIZE:]
        offset += size
        print(f"\n   [BLOCK {block_num} - BEFORE DECRYPTION]")
        print(f"   - Size Header (4 bytes, big-endian): {binascii.hexlify(size_header).decode()}")
        print(f"   - IV (12 bytes): {binascii.hexlify(iv).decode()}")
        print(f"   - Ciphertext ({len(ciphertext)} bytes): {binascii.hexlify(ciphertext[:32]).decode()}...")
        print(f"   - Total Block Size: {4 + len(iv) + len(ciphertext)} bytes")
        try:
            decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
            decrypted_blocks.append(decrypted_bytes)
            
            # Debug output AFTER decryption
            print(f"\n   [BLOCK {block_num} - AFTER DECRYPTION]")
            print(f"   - Plaintext (JSON): {decrypted_bytes.decode('utf-8')}")
            print(f"   - Plaintext Size: {len(decrypted_bytes)} bytes")
        except Exception as e:
            print(f"\n   [BLOCK {block_num} - DECRYPTION FAILED]")
            print(f"   - Error: {str(e)}")
            decrypted_blocks.append(b'{"error": "AUTH_FAILURE"}')
    return decrypted_blocks