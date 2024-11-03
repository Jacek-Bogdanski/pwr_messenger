def mod_exp(base, exponent, modulus):
    base = int(base) % int(modulus)
    result = 1
    while exponent > 0:
        if (exponent % 2) == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result

def decimal_to_hex(decimal, length):
    return hex(int(decimal))[2:].zfill(length)

def encrypt(text, e, n):
    e = int(e)
    n = int(n)
    
    max_hex_length = (n.bit_length() + 3) // 4  
    
    encrypted_chars = [
        decimal_to_hex(mod_exp(ord(char), e, n), max_hex_length)
        for char in text
    ]
    
    return ":".join(encrypted_chars)

def modular_inverse(e, fi):
    old_r, r = e, fi
    old_s, s = 1, 0

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    return old_s % fi

def get_key_pair(P, Q, E):
    N = P * Q
    fi = (P - 1) * (Q - 1)
    D = modular_inverse(E, fi)
    return N, D

def decrypt(encrypted_message, server_d, server_n):
    encrypted_chunks = encrypted_message.split(':')

    decrypted_message = ""
    for hex_chunk in encrypted_chunks:
        encrypted_int = int(hex_chunk, 16)
        decrypted_int = pow(encrypted_int, server_d, server_n)
        decrypted_message_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
        decrypted_message += decrypted_message_bytes.decode('utf-8', errors='ignore')

    return decrypted_message