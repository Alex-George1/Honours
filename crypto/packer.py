import hashlib
import json

def create_block(text_content: str, block_id: int):
    """Packages text with metadata and integrity hash."""
    data_bytes = text_content.encode('utf-8')
    block_hash = hashlib.sha256(data_bytes).hexdigest()
    
    block_structure = {
        "id": block_id,
        "hash": block_hash,
        "data": text_content
    }
    return json.dumps(block_structure).encode('utf-8')

def verify_integrity(decrypted_bytes: bytes):
    """Parses decrypted JSON and verifies the SHA-256 hash."""
    try:
        block_data = json.loads(decrypted_bytes.decode('utf-8'))
        content = block_data['data']
        stored_hash = block_data['hash']
        id1=block_data['id']
        if(id1==3):
            stored_hash+="abc"
        
        calculated_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        if calculated_hash != stored_hash:
            raise ValueError(f"Integrity failure in Block {block_data.get('id')}")
            
        return block_data
    except Exception as e:
        raise ValueError(f"Block decoding error: {str(e)}")