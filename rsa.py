import math

def encode_public_key(n, e):
    max_length = max(len(str(n)), len(str(e)))
    n_str = str(n).zfill(max_length)
    e_str = str(e).zfill(max_length)
    return int(n_str + e_str)

def decode_public_key(encoded_num):
    encoded_str = str(encoded_num)
    half_length = len(encoded_str) // 2
    n = int(encoded_str[:half_length])
    e = int(encoded_str[half_length:])
    return n, e

def get_server_pub(current_app):
    p = current_app.config['SERVER_RSA_P']
    q= current_app.config['SERVER_RSA_Q']
    n = p * q
    return encode_public_key(n, current_app.config['SERVER_RSA_E'])


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


def mod_exp(base, exponent, modulus):
    base = int(base) % int(modulus)
    result = 1
    while exponent > 0:
        if (exponent % 2) == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result

def int_to_n_bit_string(value, n):
    binary_string = bin(value)[2:]
    return binary_string.zfill(n)

def bit_string_to_int(bit_string):
    return int(bit_string, 2)

def binary_string_to_text(binary_string):
    text = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    return text

def encrypt(text, e, n):
    e = int(e)
    n = int(n)
    chunk_length = math.ceil(math.log(n, 2))

    binary_data = ''.join(int_to_n_bit_string(ord(char), 8) for char in text)
    if len(binary_data) % chunk_length != 0:
        binary_data = binary_data.ljust(len(binary_data) + chunk_length - (len(binary_data) % chunk_length), '0')
    
    binary_data = binary_data.ljust(len(binary_data) + chunk_length, '0')
    
    encrypted_binary = ''
    while binary_data:
        chunk = binary_data[:chunk_length]
        binary_data = binary_data[chunk_length:]
        encrypted_value = mod_exp(bit_string_to_int(chunk), e, n)
        encrypted_binary += int_to_n_bit_string(encrypted_value, chunk_length)
    
    return binary_string_to_text(encrypted_binary)

def decrypt(encrypted_text, d, n):
    d = int(d)
    n = int(n)
    chunk_length = math.ceil(math.log(n, 2))

    binary_encrypted = ''.join(int_to_n_bit_string(ord(char), 8) for char in encrypted_text)

    decrypted_binary = ""
    while binary_encrypted:
        current_chunk = binary_encrypted[:chunk_length]
        binary_encrypted = binary_encrypted[chunk_length:]
        chunk_value = bit_string_to_int(current_chunk)
        decoded_value = mod_exp(chunk_value, d, n)
        decrypted_binary += int_to_n_bit_string(decoded_value, chunk_length)

    decrypted_text = binary_string_to_text(decrypted_binary)
    
    return decrypted_text.rstrip('\x00')