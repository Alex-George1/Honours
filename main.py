import os
import binascii
from crypto.pki import generate_keys, encrypt_session_key, decrypt_session_key
from crypto.packer import create_block, verify_integrity
from crypto.engine import encrypt_payload, decrypt_payload
from crypto.image_codec import binary_to_image, image_to_binary

def run():
    INPUT_FILE = "input_text.txt"
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Please create it first.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        raw_content = f.read()

    print("="*60)
    print(" PHASE 1: SENDER SIDE (Hybrid Encryption)")
    print("="*60)

    # 1. RSA & Session Key Generation
    print("[Step 1] Generating RSA Key Pair and random AES-256 session key...")
    private_key, public_key = generate_keys()
    session_key = os.urandom(32)
    print(f"   - Session Key (First 16 hex): {binascii.hexlify(session_key[:8]).decode()}...")

    # 2. Packaging
    paragraphs = [p.strip() for p in raw_content.split('\n') if p.strip()]
    packaged_blocks = [create_block(p, i + 1) for i, p in enumerate(paragraphs)]
    print(f"[Step 2] Packaged {len(paragraphs)} blocks with SHA-256 integrity hashes.")

    # 3. AES Encryption
    encrypted_data = encrypt_payload(packaged_blocks, session_key)
    print(f"[Step 3] Encrypted blocks using AES-GCM. Size: {len(encrypted_data)} bytes.")

    # 4. RSA Wrapping
    wrapped_key = encrypt_session_key(session_key, public_key)
    print(f"[Step 4] Wrapped AES key with RSA Public Key. Wrapped Size: {len(wrapped_key)} bytes.")

    # 5. Transmission Assembly
    key_len_bytes = len(wrapped_key).to_bytes(4, 'big')
    transmission = key_len_bytes + wrapped_key + encrypted_data
    print(f"[Step 5] Final Payload Assembled. Total size: {len(transmission)} bytes.")

    # 6. Image Encoding (Steganographic Output)
    IMAGE_OUTPUT = "encrypted_image.png"
    print(f"[Step 6] Encoding transmission into RGB image...")
    encoding_info = binary_to_image(transmission, IMAGE_OUTPUT)
    print(f"   - Image created: {encoding_info['image_dimensions'][0]}x{encoding_info['image_dimensions'][1]} pixels")
    print(f"   - Saved to: {IMAGE_OUTPUT}")

    print("\n" + "="*60)
    print(" PHASE 2: RECEIVER SIDE (Hybrid Decryption)")
    print("="*60)

    # 0. Image Decoding (Recover Binary from Image)
    print(f"[Step 0] Decoding binary data from RGB image...")
    recovered_transmission = image_to_binary(IMAGE_OUTPUT)
    print(f"   - Recovered {len(recovered_transmission)} bytes from image.")

    # 1. Extraction
    rec_key_len = int.from_bytes(recovered_transmission[:4], 'big')
    rec_wrapped_key = recovered_transmission[4 : 4 + rec_key_len]
    rec_cipher_data = recovered_transmission[4 + rec_key_len :]
    print(f"[Step 1] Extracted {rec_key_len} bytes of wrapped key from header.")

    # 2. RSA Unwrapping
    recovered_aes_key = decrypt_session_key(rec_wrapped_key, private_key)
    print("[Step 2] Successfully unwrapped AES session key using Private Key.")

    # 3. AES Decryption
    decrypted_raw_list = decrypt_payload(rec_cipher_data, recovered_aes_key)
    print(f"[Step 3] Decrypted {len(decrypted_raw_list)} blocks from the binary stream.")

    # 4. Integrity Check
    print("\n[Step 4] Verifying Block Integrity:")
    for raw_bytes in decrypted_raw_list:
        try:
            data = verify_integrity(raw_bytes)
            print(f"   [OK] Block {data['id']} Hash Verified: {data['hash'][:10]}...")
            print(f"        Data: {data['data']}")
        except Exception as e:
            print(f"   [FAILED] {e}")

if __name__ == "__main__":
    run()