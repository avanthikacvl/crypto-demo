from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import time

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# --- 1. MATHEMATICAL VALIDATION ---
def is_prime(n):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0: return False
        i += 6
    return True

def prime_factors(n):
    i = 2
    factors = set()
    while i * i <= n:
        if n % i: i += 1
        else:
            n //= i
            factors.add(i)
    if n > 1: factors.add(n)
    return factors

def is_primitive_root(g, p):
    if not is_prime(p): return False
    phi = p - 1
    factors = prime_factors(phi)
    for factor in factors:
        if pow(g, phi // factor, p) == 1:
            return False
    return True

# --- 2. THE DISCRETE LOGARITHM BRUTE-FORCER (EVE) ---
def crack_dlp(g, A, p):
    start_time = time.time()
    limit = min(p, 5000000) 
    for x in range(1, limit):
        if pow(g, x, p) == A:
            return x, time.time() - start_time
    return None, time.time() - start_time

# --- 3. AES ENCRYPTION ---
def aes_encrypt(secret_int, plaintext):
    if not plaintext: return None, None
    key = hashlib.sha256(str(secret_int).encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def aes_decrypt(secret_int, iv, ct):
    if not ct: return None
    key = hashlib.sha256(str(secret_int).encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, base64.b64decode(iv))
    pt = unpad(cipher.decrypt(base64.b64decode(ct)), AES.block_size).decode('utf-8')
    return pt

# --- 4. DIGITAL SIGNATURES (STS DEFENSE) ---
def simulate_rsa_signature(data_value, private_key_sim):
    payload = f"{data_value}_{private_key_sim}".encode('utf-8')
    return hashlib.sha256(payload).hexdigest()[:16]

# --- MAIN ROUTE ---
@app.route('/compute', methods=['POST'])
def compute():
    data = request.json
    
    p = int(data.get('p'))
    g = int(data.get('g'))
    a = int(data.get('a'))
    b = int(data.get('b'))
    message = data.get('message', '')
    
    if not is_prime(p):
        return jsonify({'error': f"Mathematical Validation Failed: {p} is NOT a prime number!"})
    if not is_primitive_root(g, p):
        return jsonify({'error': f"Mathematical Validation Failed: {g} is NOT a primitive root modulo {p}."})

    mitm_active = data.get('mitm_active', False)
    auth_active = data.get('auth_active', False)
    eve_active = data.get('eve_active', False)

    A = pow(g, a, p)
    B = pow(g, b, p)

    # VISIBLE RSA IDENTITY KEYS
    alice_rsa_priv = "ALICE_PRV_92A"
    alice_rsa_pub = "ALICE_PUB_74B"
    bob_rsa_priv = "BOB_PRV_31C"
    bob_rsa_pub = "BOB_PUB_88D"

    sig_A = simulate_rsa_signature(A, alice_rsa_priv) if auth_active else None
    sig_B = simulate_rsa_signature(B, bob_rsa_priv) if auth_active else None

    cracked_a = None
    crack_time = None
    if eve_active:
        cracked_a, crack_time = crack_dlp(g, A, p)

    if not mitm_active:
        secret_shared = pow(B, a, p)
        iv, ciphertext = aes_encrypt(secret_shared, message)
        decrypted_message = aes_decrypt(secret_shared, iv, ciphertext) if ciphertext else ""

        return jsonify({
            'success': True,
            'mitm_active': False,
            'eve_active': eve_active,
            'cracked_a': cracked_a,
            'crack_time': round(crack_time, 5) if crack_time else 0,
            'A': A, 'B': B, 'secret': secret_shared,
            'ciphertext': ciphertext,
            'decrypted_message': decrypted_message,
            'alice_rsa_priv': alice_rsa_priv, 'alice_rsa_pub': alice_rsa_pub
        })
    else:
        m_a = int(data.get('m_a'))
        m_b = int(data.get('m_b'))
        M_A = pow(g, m_a, p)
        M_B = pow(g, m_b, p)
        
        if auth_active:
            expected_sig_for_M_A = simulate_rsa_signature(M_A, alice_rsa_priv)
            return jsonify({
                'success': True,
                'mitm_active': True,
                'auth_active': True,
                'A': A, 'B': B, 'M_A': M_A, 'M_B': M_B,
                'sig_A': sig_A, 'expected_sig_for_M_A': expected_sig_for_M_A,
                'alice_rsa_priv': alice_rsa_priv, 'alice_rsa_pub': alice_rsa_pub
            })
        else:
            secret_alice = pow(M_A, a, p)
            secret_bob = pow(M_B, b, p)
            iv_A, ciphertext_from_alice = aes_encrypt(secret_alice, message)
            mallorys_decrypted_msg = aes_decrypt(secret_alice, iv_A, ciphertext_from_alice) if ciphertext_from_alice else ""

            return jsonify({
                'success': True,
                'mitm_active': True,
                'auth_active': False,
                'A': A, 'B': B, 'M_A': M_A, 'M_B': M_B,
                'secret_alice': secret_alice, 'secret_bob': secret_bob,
                'ciphertext_from_alice': ciphertext_from_alice,
                'mallorys_decrypted_msg': mallorys_decrypted_msg
            })

if __name__ == '__main__':
    app.run(debug=True, port=5000)