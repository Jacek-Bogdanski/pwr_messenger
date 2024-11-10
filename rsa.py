import math

def decimal_to_hex(decimal, length):
    return hex(int(decimal))[2:].zfill(length)

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
    binary_string = bin(value & ((1 << n) - 1))[2:]
    return binary_string.zfill(n)

def bit_string_to_int(bit_string):
    return int(bit_string, 2)

def binary_string_to_text(binary_string):
    return ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))


## po nowemu - podział na chunki
def encrypt(text, e, n):
    e = int(e)
    n = int(n)
    
    chunk_length = math.floor(math.log(n,2))
    buffer = ""
    current = ""
    coded = 0
    output = ""
    test = ""
    
    for letter in text:
        buffer += int_to_n_bit_string(ord(letter),8)
        
    if len(buffer) % chunk_length != 0:
        padding_length = chunk_length - (len(buffer) % chunk_length)
        buffer += "0" * padding_length
                
    while len(buffer) > chunk_length:
        current = buffer[:chunk_length]
        buffer = buffer[chunk_length:]
        coded = mod_exp(bit_string_to_int(current), e, n)
        output += int_to_n_bit_string(coded,chunk_length) 
        
    if len(output) % 8 != 0:
        padding_length = 8 - (len(output) % 8)
        output += "0" * padding_length
    
    return binary_string_to_text(output)
    

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


## po staremu - szyfrowanie znak po znaku oddzielone :
def decrypt(encrypted_message, server_d, server_n):
    encrypted_chunks = encrypted_message.split(':')

    decrypted_message = ""
    for hex_chunk in encrypted_chunks:
        encrypted_int = int(hex_chunk, 16)
        decrypted_int = pow(encrypted_int, server_d, server_n)
        decrypted_message_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
        decrypted_message += decrypted_message_bytes.decode('utf-8', errors='ignore')

    return decrypted_message