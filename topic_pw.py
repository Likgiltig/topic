import sys, os, itertools, hashlib, base64, argparse, getpass
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Tuple, List, Union, Generator

# --- Configuration Constants ---
DEFAULT_OUTPUT_IMAGE_FILENAME = "output.png"
BITS_FOR_FILENAME_LENGTH = 16      # 2 bytes for filename length in bits
BITS_FOR_DATA_LENGTH = 64          # 8 bytes for encrypted data length in bits
CHANNELS_TO_USE = 4                # 4 for RGBA (script converts to RGBA)
SALT_SIZE_BYTES = 16               # 16 bytes for PBKDF2 salt
PBKDF2_ITERATIONS = 100000         # Iteration count for PBKDF2 (higher is more secure)

# --- Helper Functions ---

def print_verbose(message: str, verbose: bool = True) -> None:
    """Prints a message if verbose output is enabled."""
    if verbose:
        print(f"[INFO] {message}")

def generate_key_from_password(password: str, salt: bytes, verbose: bool = True) -> bytes:
    """
    Generates a Fernet-compatible key from a password and salt using PBKDF2HMAC.
    """
    print_verbose("Generating encryption key from password and salt...", verbose)
    if not password:
        print("[ERROR] Password cannot be empty."); sys.exit(1)
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        fernet_key = base64.urlsafe_b64encode(key)
        print_verbose("Key derived successfully.", verbose)
        return fernet_key
    except Exception as e:
        print(f"[ERROR] Could not generate key from password: {e}")
        sys.exit(1)

def int_to_bits(n: int, bit_count: int) -> str:
    """Converts a non-negative integer to a fixed-width bit string."""
    if n < 0:
        raise ValueError("Integer cannot be negative for bit conversion.")
    if n >= (1 << bit_count):
        raise ValueError(f"Integer {n} is too large for {bit_count} bits (max: {(1 << bit_count) - 1}).")
    return format(n, f'0{bit_count}b')

def bits_to_int(bit_string: str) -> int:
    """Converts a bit string to an integer."""
    if not bit_string: return 0
    if not all(c in '01' for c in bit_string):
        raise ValueError("Invalid character in bit string. Only '0' or '1' allowed.")
    return int(bit_string, 2)

def bytes_to_bits(byte_data: bytes) -> str:
    """Converts bytes to a bit string."""
    return ''.join(format(byte, '08b') for byte in byte_data)

def bits_to_bytes(bit_string: str) -> bytes:
    """Converts a bit string (length multiple of 8) back to bytes."""
    if not bit_string: return b''
    if len(bit_string) % 8 != 0:
        raise ValueError("Bit string length must be a multiple of 8 for byte conversion.")
    if not all(c in '01' for c in bit_string):
        raise ValueError("Invalid character in bit string for byte conversion.")
    return bytes(int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8))

def embed_data_in_image(base_image_filepath: str, data_bits: str, output_image_filepath: str, verbose: bool = True) -> None:
    """Embeds data bits into the LSB of image pixels."""
    print_verbose(f"Opening base image '{base_image_filepath}' for embedding...", verbose)
    try:
        img = Image.open(base_image_filepath).convert("RGBA")
    except FileNotFoundError:
        print(f"[ERROR] Base image file '{base_image_filepath}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Could not open/process base image '{base_image_filepath}': {e}")
        sys.exit(1)
    width, height = img.size
    max_bits = width * height * CHANNELS_TO_USE
    print_verbose(f"Base image: {width}x{height}, Max embeddable bits: {max_bits}", verbose)
    print_verbose(f"Total bits to embed: {len(data_bits)}", verbose)
    if len(data_bits) > max_bits:
        print(f"[ERROR] Not enough space in image. Required: {len(data_bits)}, Available: {max_bits}.")
        sys.exit(1)
    print_verbose("Embedding data into image pixels (LSB)...", verbose)
    img_data = img.load()
    data_iter = iter(data_bits)
    pixels_modified_count = 0
    for y, x in itertools.product(range(height), range(width)):
        pixel_values = list(img_data[x, y])
        modified_in_pixel = False
        for i in range(CHANNELS_TO_USE):
            try:
                bit_to_embed = next(data_iter)
                pixel_values[i] = (pixel_values[i] & 0xFE) | int(bit_to_embed)
                modified_in_pixel = True
            except StopIteration:
                img_data[x, y] = tuple(pixel_values)
                if modified_in_pixel: pixels_modified_count +=1
                print_verbose(f"Data embedded, modifying approx {pixels_modified_count} pixels.", verbose)
                img.save(output_image_filepath, "PNG")
                print_verbose(f"Steganographic image saved as '{output_image_filepath}'", verbose)
                return
        img_data[x, y] = tuple(pixel_values)
        if modified_in_pixel: pixels_modified_count +=1
    if pixels_modified_count * CHANNELS_TO_USE < len(data_bits):
         print("[WARNING] Not all data bits may have been embedded despite loop completion. Check logic.")

def extract_bits_from_image_generator(stego_image_filepath: str, verbose: bool = True) -> Generator[str, None, None]:
    """Generator to extract LSB bits sequentially from image pixels."""
    print_verbose(f"Opening steganographic image '{stego_image_filepath}' for extraction...", verbose)
    try:
        img = Image.open(stego_image_filepath).convert("RGBA")
    except FileNotFoundError:
        print(f"[ERROR] Steganographic image file '{stego_image_filepath}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Could not open/process steganographic image '{stego_image_filepath}': {e}")
        sys.exit(1)
    width, height = img.size
    print_verbose(f"Steganographic image dimensions: {width}x{height}", verbose)
    img_data = img.load()
    for y, x in itertools.product(range(height), range(width)):
        pixel = img_data[x, y]
        for i in range(CHANNELS_TO_USE):
            yield str(pixel[i] & 1)

def extract_specific_bits(bit_generator: Generator[str, None, None], num_bits: int) -> str:
    """Extracts a specific number of bits from the bit generator."""
    bits = list(itertools.islice(bit_generator, num_bits))
    if len(bits) != num_bits:
        raise ValueError(f"Could not extract {num_bits} bits. End of image data. Got {len(bits)}.")
    return "".join(bits)

# --- Main Actions ---

def encrypt_action(data_filepath: str, base_image_filepath: str, output_stego_image_filepath: str, verbose: bool = True) -> None:
    """Encrypts data and its filename, then embeds into an image using a password."""
    print_verbose("--- Starting Encryption Process ---", verbose)
    password = getpass.getpass("Enter encryption password: ")
    if not password:
        print("[ERROR] Password cannot be empty. Aborting.")
        sys.exit(1)
    password_confirm = getpass.getpass("Confirm encryption password: ")
    if password != password_confirm:
        print("[ERROR] Passwords do not match. Aborting.")
        sys.exit(1)
    salt = os.urandom(SALT_SIZE_BYTES)
    key = generate_key_from_password(password, salt, verbose)
    fernet = Fernet(key)
    print_verbose(f"Reading data file '{data_filepath}'...", verbose)
    try:
        with open(data_filepath, "rb") as f:
            data_bytes = f.read()
        original_filename = os.path.basename(data_filepath)
        print_verbose(f"Read {len(data_bytes)} bytes from '{original_filename}'.", verbose)
    except FileNotFoundError:
        print(f"[ERROR] Data file '{data_filepath}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Could not read data file '{data_filepath}': {e}")
        sys.exit(1)
    print_verbose("Encrypting data...", verbose)
    encrypted_bytes = fernet.encrypt(data_bytes)
    print_verbose(f"Data encrypted to {len(encrypted_bytes)} bytes.", verbose)
    try:
        salt_bits = bytes_to_bits(salt)
        filename_bytes = original_filename.encode('utf-8')
        filename_bits = bytes_to_bits(filename_bytes)
        filename_length_bits_str = int_to_bits(len(filename_bits), BITS_FOR_FILENAME_LENGTH)
        
        encrypted_data_bits = bytes_to_bits(encrypted_bytes)
        data_length_bits_str = int_to_bits(len(encrypted_data_bits), BITS_FOR_DATA_LENGTH)
    except ValueError as e:
        print(f"[ERROR] Failed to convert metadata to bits: {e}")
        sys.exit(1)
    # Order: Salt, Filename Length, Filename, Data Length, Encrypted Data
    total_bits_to_embed = (
        salt_bits +
        filename_length_bits_str +
        filename_bits +
        data_length_bits_str +
        encrypted_data_bits)
    total_len = len(total_bits_to_embed)
    print_verbose(
        f"Total bits to embed: {total_len} ("
        f"{len(salt_bits)} salt + {BITS_FOR_FILENAME_LENGTH} fn_len + {len(filename_bits)} fn + "
        f"{BITS_FOR_DATA_LENGTH} data_len + {len(encrypted_data_bits)} data)",
        verbose)
    embed_data_in_image(base_image_filepath, total_bits_to_embed, output_stego_image_filepath, verbose)
    print_verbose("--- Encryption Process Complete ---", verbose)
    print(f"Encryption successful. Output image: '{output_stego_image_filepath}'")
    print(f"IMPORTANT: To decrypt, you will need this steganographic image and the password.")

def decrypt_action(stego_image_filepath: str, verbose: bool = True) -> None:
    """Extracts, decrypts, and saves data from a steganographic image using a password."""
    print_verbose("--- Starting Decryption Process ---", verbose)
    password = getpass.getpass("Enter decryption password: ")
    if not password:
        print("[ERROR] Password cannot be empty. Aborting.")
        sys.exit(1)
    bit_extractor_gen = extract_bits_from_image_generator(stego_image_filepath, verbose)
    try:
        # 1. Extract Salt
        print_verbose(f"Extracting salt ({SALT_SIZE_BYTES * 8} bits)...", verbose)
        salt_bits = extract_specific_bits(bit_extractor_gen, SALT_SIZE_BYTES * 8)
        salt = bits_to_bytes(salt_bits)
        # Generate key with extracted salt and provided password
        key = generate_key_from_password(password, salt, verbose)
        fernet = Fernet(key)
        # 2. Extract Filename Length
        print_verbose(f"Extracting filename length ({BITS_FOR_FILENAME_LENGTH} bits)...", verbose)
        fn_len_bits_str = extract_specific_bits(bit_extractor_gen, BITS_FOR_FILENAME_LENGTH)
        filename_length_in_bits = bits_to_int(fn_len_bits_str)
        print_verbose(f"Extracted filename length: {filename_length_in_bits} bits.", verbose)
        if not (0 <= filename_length_in_bits < (1 << BITS_FOR_FILENAME_LENGTH) and filename_length_in_bits % 8 == 0):
            print("[ERROR] Invalid filename length. Data corruption likely.")
            sys.exit(1)
        # 3. Extract Filename
        print_verbose(f"Extracting filename ({filename_length_in_bits} bits)...", verbose)
        filename_bits = extract_specific_bits(bit_extractor_gen, filename_length_in_bits)
        decrypted_filename = bits_to_bytes(filename_bits).decode('utf-8')
        print_verbose(f"Extracted filename: '{decrypted_filename}'", verbose)
        # 4. Extract Data Length
        print_verbose(f"Extracting data length ({BITS_FOR_DATA_LENGTH} bits)...", verbose)
        data_len_bits_str = extract_specific_bits(bit_extractor_gen, BITS_FOR_DATA_LENGTH)
        encrypted_data_length_in_bits = bits_to_int(data_len_bits_str)
        print_verbose(f"Extracted data length: {encrypted_data_length_in_bits} bits.", verbose)
        if not (0 <= encrypted_data_length_in_bits < (1 << BITS_FOR_DATA_LENGTH) and (encrypted_data_length_in_bits % 8 == 0 or encrypted_data_length_in_bits == 0)):
            print("[ERROR] Invalid data length. Data corruption likely.")
            sys.exit(1)
        # 5. Extract Encrypted Data
        print_verbose(f"Extracting encrypted data ({encrypted_data_length_in_bits} bits)...", verbose)
        encrypted_data_bits = extract_specific_bits(bit_extractor_gen, encrypted_data_length_in_bits)
        encrypted_bytes = bits_to_bytes(encrypted_data_bits)
        print_verbose(f"Converted to {len(encrypted_bytes)} encrypted bytes.", verbose)
    except ValueError as e: # Covers issues from bit/byte conversions, int conversions, insufficient bits
        print(f"[ERROR] Failed during data extraction/conversion: {e}")
        sys.exit(1)
    except UnicodeDecodeError:
        print("[ERROR] Failed to decode filename (UTF-8). Data might be corrupted.")
        sys.exit(1)
    except Exception as e: # Catch-all for other unexpected errors during extraction
        print(f"[ERROR] An unexpected error occurred during data extraction: {e}")
        sys.exit(1)
    # 6. Decrypt Data
    print_verbose("Decrypting data...", verbose)
    if not encrypted_bytes:
        decrypted_bytes = b""
        print_verbose("No data to decrypt (0 bytes).", verbose)
    else:
        try:
            decrypted_bytes = fernet.decrypt(encrypted_bytes)
            print_verbose(f"Data decrypted successfully ({len(decrypted_bytes)} bytes).", verbose)
        except Exception as e: # Catches InvalidToken from Fernet, etc.
            print(f"[ERROR] Decryption failed. Incorrect password or corrupted data. Error: {e}")
            sys.exit(1)
    # 7. Save Decrypted Data
    output_filepath = decrypted_filename
    print_verbose(f"Saving decrypted data to '{output_filepath}'...", verbose)
    try:
        # Prevent overwriting critical files (simple check)
        if output_filepath in (os.path.basename(sys.argv[0]), stego_image_filepath) or \
           os.path.abspath(output_filepath) == os.path.abspath(stego_image_filepath):
            print(f"[ERROR] Output filename '{output_filepath}' conflicts with script/stego image. Aborting.")
            sys.exit(1)
        if os.path.isdir(output_filepath):
             print(f"[ERROR] Output filename '{output_filepath}' is an existing directory. Aborting.")
             sys.exit(1)
        with open(output_filepath, "wb") as f:
            f.write(decrypted_bytes)
        print_verbose(f"Decrypted data saved to '{output_filepath}'.", verbose)
    except Exception as e:
        print(f"[ERROR] Could not save decrypted data to '{output_filepath}': {e}")
        sys.exit(1)
    print_verbose("--- Decryption Process Complete ---", verbose)
    print(f"Decryption successful. Output file: '{output_filepath}'")

def print_usage_examples():
    """Print usage examples for the script."""
    filename = os.path.basename(__file__)
    print("Description:")
    print("  This script enables you to hide and encrypt files within images using LSB steganography.")
    print("  It provides two main functions: encrypting a file into an image, and decrypting it.")
    print("\nUsage Examples:")
    print("\n  1. Encrypt a file into an image:")
    print(f"     python {filename} encrypt secret.txt cover.png -o hidden.png")
    print("     This encrypts 'secret.txt' inside 'cover.png' and saves as 'hidden.png'")
    print("\n  2. Encrypt with default output name:")
    print(f"     python {filename} encrypt confidential.docx cover.jpg")
    print("     This encrypts 'confidential.docx' inside 'cover.jpg' and saves as 'output.png'")
    print("\n  3. Encrypt with quiet mode (less verbose output):")
    print(f"     python {filename} encrypt secret.txt cover.png -o hidden.png -q")
    print("\n  4. Decrypt a file from a steganographic image:")
    print(f"     python {filename} decrypt hidden.png")
    print("     This extracts and decrypts the hidden file from 'hidden.png'\n")

# --- Main Execution ---
def main():
    print(f'''
    ████████  ██████     ██████  ██  ██████         ██████  ██     ██ 
       ██    ██    ██    ██   ██ ██ ██              ██   ██ ██     ██ 
       ██    ██    ██    ██████  ██ ██              ██████  ██  █  ██ 
       ██    ██    ██    ██      ██ ██              ██      ██ ███ ██ 
       ██     ██████  ██ ██      ██  ██████  █████  ██       ███ ███  
    ''')
    # If no arguments are provided, print usage examples and exit
    if len(sys.argv) == 1:
        print_usage_examples()
        sys.exit(1)
    subparsers = parser.add_subparsers(dest="action", required=True, help="Action: 'encrypt' or 'decrypt'")
    # Encrypt arguments
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt and embed data into an image.")
    encrypt_parser.add_argument("data_file", help="Path to the data file to hide.")
    encrypt_parser.add_argument("base_image", help="Path to the base image file for embedding.")
    encrypt_parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_IMAGE_FILENAME,
                                help=f"Output steganographic image (default: {DEFAULT_OUTPUT_IMAGE_FILENAME}).")
    encrypt_parser.add_argument("-q", "--quiet", action="store_false", dest="verbose", help="Suppress verbose output.")
    # Decrypt arguments
    decrypt_parser = subparsers.add_parser("decrypt", help="Extract and decrypt data from an image.")
    decrypt_parser.add_argument("stego_image", help="Path to the steganographic image.")
    decrypt_parser.add_argument("-q", "--quiet", action="store_false", dest="verbose", help="Suppress verbose output.")
    args = parser.parse_args()
    verbose = getattr(args, 'verbose', True)
    # File existence checks
    if args.action == "encrypt":
        if not os.path.isfile(args.data_file):
            print(f"[ERROR] Data file not found: {args.data_file}"); sys.exit(1)
        if not os.path.isfile(args.base_image):
            print(f"[ERROR] Base image not found: {args.base_image}"); sys.exit(1)
        encrypt_action(args.data_file, args.base_image, args.output, verbose)
    elif args.action == "decrypt":
        if not os.path.isfile(args.stego_image):
            print(f"[ERROR] Stego image not found: {args.stego_image}"); sys.exit(1)
        decrypt_action(args.stego_image, verbose)

if __name__ == "__main__":
    main()
