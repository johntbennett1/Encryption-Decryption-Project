import hashlib


# ── Key Generation Helpers ──────────────────────────────────────────────────

def compute_keypair(p: int, q: int, e: int = 65537) -> dict:
    """
    Returns a dict with all key material derived from primes p and q.
    Keys: p, q, e, d, n, d_p, d_q, q_inv
    """
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return {
        "p":     p,
        "q":     q,
        "e":     e,
        "d":     d,
        "n":     n,
        "d_p":   d % (p - 1),
        "d_q":   d % (q - 1),
        "q_inv": pow(q, -1, p),
    }


# ── Core RSA Operations ─────────────────────────────────────────────────────

def encrypt(message: str, e: int, n: int) -> int:
    """Encrypts a plaintext string. Returns ciphertext as an integer."""
    m = int(message.encode().hex(), 16)
    return pow(m, e, n)


def decrypt(ciphertext: int, key: dict) -> str:
    """
    Decrypts an integer ciphertext using CRT for efficiency.
    Accepts the key dict from compute_keypair().
    Returns the plaintext string.
    """
    m_p = pow(ciphertext, key["d_p"], key["p"])
    m_q = pow(ciphertext, key["d_q"], key["q"])
    h   = (key["q_inv"] * (m_p - m_q)) % key["p"]
    m   = m_q + h * key["q"]

    hex_str = hex(m)[2:]
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return bytes.fromhex(hex_str).decode("utf-8")


def sign(message: str, d: int, n: int) -> int:
    """Signs a message with the private key. Returns signature as an integer."""
    hash_int = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    return pow(hash_int, d, n)


def verify(message: str, signature: int, e: int, n: int) -> bool:
    """Verifies a signature against the original message. Returns True if valid."""
    hash_int     = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    hash_from_sig = pow(signature, e, n)
    return hash_from_sig == hash_int


# ── Convenience Wrappers ────────────────────────────────────────────────────

def encrypt_and_sign(message: str, key: dict) -> tuple[int, int]:
    """
    Encrypts and signs a message in one call.
    Returns (ciphertext, signature) as a tuple of integers.
    """
    c   = encrypt(message, key["e"], key["n"])
    sig = sign(message, key["d"], key["n"])
    return c, sig


def decrypt_and_verify(ciphertext: int, signature: int, key: dict) -> tuple[str, bool]:
    """
    Decrypts and verifies in one call.
    Returns (plaintext, signature_valid) as a tuple.
    """
    plaintext = decrypt(ciphertext, key)
    valid     = verify(plaintext, signature, key["e"], key["n"])
    return plaintext, valid


# ── Example Usage ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    p = int("40992408416096028179761232532587525402909285099086220133403920525409552083528606215439915948260875718893797824735118621138192569490840098061133066650255608065609253901288801302035441884878187944219033")
    q = int("41184172451867371867686906412307989908388177848827102865167949679167771021417488428983978626721272105583120243720400358313998904049755363682307706550788498535402989510396285940007396534556364659633739")

    key = compute_keypair(p, q)

    message = "Discrete Math"
    c, sig = encrypt_and_sign(message, key)
    plaintext, valid = decrypt_and_verify(c, sig, key)

    print("Decrypted:", plaintext)
    print("Signature valid:", valid)