import base64
from typing import Tuple
try:
    from Cryptodome.Cipher import DES, DES3, AES
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.Padding import pad, unpad
except Exception as e:
    print("ERROR")
    raise

BLOCK_SIZES = {
    "DES": 8,
    "3DES": 8,
    "AES-256": 16,
}

KEY_SIZES = {
    "DES": 8,         # 64 bits 
    "3DES": 24,       # 192 bits 
    "AES-256": 32,    # 256 bits
}

def ensure_bytes(s: str) -> bytes:
    
    s = s.strip()
    if s.lower().startswith("hex:"):
        return bytes.fromhex(s[4:])
    if s.lower().startswith("0x"):
        return bytes.fromhex(s[2:])
    return s.encode("utf-8")

def adjust_key(alg: str, key: bytes) -> bytes:
    target = KEY_SIZES[alg]
    if alg == "3DES":
  
        if len(key) < 24:
            from Cryptodome.Random import get_random_bytes
            key = key + get_random_bytes(24 - len(key))
        elif len(key) > 24:
            key = key[:24]

        key = DES3.adjust_key_parity(key)
        try:
            DES3.new(key, DES3.MODE_CBC, iv=b"\x00"*8)
        except ValueError:
            
            from Cryptodome.Random import get_random_bytes
            base = key[:16]  
            while True:
                candidate = DES3.adjust_key_parity(base + get_random_bytes(8))
                try:
                    DES3.new(candidate, DES3.MODE_CBC, iv=b"\x00"*8)
                    key = candidate
                    break
                except ValueError:
                    continue
        return key

    # DES / AES-256 
    if len(key) < target:
        from Cryptodome.Random import get_random_bytes
        key = key + get_random_bytes(target - len(key))
    if len(key) > target:
        key = key[:target]
    return key

def adjust_iv(alg: str, iv: bytes) -> bytes:
   
    bs = BLOCK_SIZES[alg]
    if len(iv) < bs:
        iv = iv + get_random_bytes(bs - len(iv))
    if len(iv) > bs:
        iv = iv[:bs]
    return iv

def build_cipher(alg: str, key: bytes, iv: bytes):
    if alg == "DES":
        return DES.new(key, DES.MODE_CBC, iv=iv)
    elif alg == "3DES":
        return DES3.new(key, DES3.MODE_CBC, iv=iv)
    elif alg == "AES-256":
        return AES.new(key, AES.MODE_CBC, iv=iv)
    else:
        raise ValueError("Algoritmo no soportado")

def encrypt_cbc(alg: str, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = build_cipher(alg, key, iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZES[alg]))
    return ct

def decrypt_cbc(alg: str, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = build_cipher(alg, key, iv)
    pt = unpad(cipher.decrypt(ciphertext), BLOCK_SIZES[alg])
    return pt

def print_summary(alg: str, key: bytes, iv: bytes, ct: bytes, pt: bytes):
    print("\n=== RESUMEN ===")
    print(f"Algoritmo: {alg}")
    print(f"Clave usada (hex): {key.hex()}  (len={len(key)} bytes)")
    print(f"IV usado   (hex): {iv.hex()}   (len={len(iv)} bytes)")
    print(f"Ciphertext (Base64): {base64.b64encode(ct).decode()}")
    print(f"Ciphertext (hex)   : {ct.hex()}")
    print(f"Texto descifrado   : {pt.decode('utf-8', errors='replace')}")
   
def main():

    alg = input("Elige algoritmo [DES / 3DES / AES-256]: ").strip().upper()
    if alg not in ("DES", "3DES", "AES-256"):
        print("Algoritmo no válido.")
        return

    key_in = input("Ingresa KEY (utf-8 o hex:): ")
    iv_in = input("Ingresa IV (utf-8 o hex:): ")
    texto_in = input("Ingresa TEXTO a cifrar: ")
   
    key_raw = ensure_bytes(key_in)
    iv_raw = ensure_bytes(iv_in)
    pt = ensure_bytes(texto_in)

    key = adjust_key(alg, key_raw)
    iv = adjust_iv(alg, iv_raw)

    ct = encrypt_cbc(alg, key, iv, pt)
    pt2 = decrypt_cbc(alg, key, iv, ct)

    print_summary(alg, key, iv, ct, pt2)

if __name__ == "__main__":
    main()
