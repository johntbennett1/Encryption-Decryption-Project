import hashlib

#Variables
p = int("40992408416096028179761232532587525402909285099086220133403920525409552083528606215439915948260875718893797824735118621138192569490840098061133066650255608065609253901288801302035441884878187944219033")
q = int("41184172451867371867686906412307989908388177848827102865167949679167771021417488428983978626721272105583120243720400358313998904049755363682307706550788498535402989510396285940007396534556364659633739")
e = 65537
d = pow(e, -1, (p-1)*(q-1))


#MSG to Encrypt
message = "Discrete Math"

d_p = d % (p-1)
d_q = d % (q-1)
q_inv = pow(q, -1, p)
m = int(message.encode().hex(), 16)

#Encrypt
c = pow(m, e, p*q)

#Sign
hash_sig = int(hashlib.sha256(message.encode()).hexdigest(), 16)
signature = pow(hash_sig, d, p*q)

#Decrypt using Chinese Remainder Theorem
m_p = pow(c, d_p, p)
m_q = pow(c, d_q, q)
h_val = (q_inv * (m_p - m_q)) % p
m_decrypted = m_q + h_val * q
hex_str = hex(m_decrypted)[2:]
if len(hex_str) % 2:
    hex_str = '0' + hex_str
text = bytes.fromhex(hex_str).decode('utf-8')
print("Decrypted Message:", text)

#Verify Signature
h_check = pow(signature, e, p*q)
if h_check == hash_sig:
    print("Signature is valid.")
else:
    print("Signature invalid.")