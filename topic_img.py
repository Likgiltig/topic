import sys, os, itertools, hashlib, base64
from PIL import Image
from cryptography.fernet import Fernet

# --- Configuration ---
MIX_IMAGE_FILE = "output.png"
BITS_FOR_FILENAME_LENGTH = 16 # Use 16 bits (2 bytes) to store the length of the filename
BITS_FOR_DATA_LENGTH = 64  # Use 64 bits (8 bytes) to store the length of the encrypted data

# --- Helper Functions ---
def print_verbose(message):
    """Prints a message if verbose output is enabled (default)."""
    print(f"[INFO] {message}")

def generate_key_from_image(image_filepath):
    """Generates a Fernet key by hashing the content of the image file."""
    print_verbose(f"Generating encryption key from image: '{image_filepath}'...")
    try:
        with open(image_filepath, "rb") as f:
            image_bytes = f.read()
        hasher = hashlib.sha256()
        hasher.update(image_bytes)
        derived_key = base64.urlsafe_b64encode(hasher.digest())
        print_verbose("Key derived successfully from image hash.")
        return derived_key
    except FileNotFoundError:
        print(f"[ERROR] Original image file '{image_filepath}' not found. This image is required to derive the encryption/decryption key.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Could not generate key from image '{image_filepath}': {e}")
        sys.exit(1)

def int_to_bits(n, bit_count):
    """Converts an integer to a fixed-width bit string."""
    if n >= (1 << bit_count):
        raise ValueError(f"Integer {n} is too large to be represented in {bit_count} bits.")
    return format(n, f'0{bit_count}b')

def bits_to_int(bit_string):
    """Converts a bit string to an integer."""
    if not bit_string:
        return 0
    return int(bit_string, 2)

def bytes_to_bits(byte_data):
    """Converts bytes to a bit string."""
    return ''.join(format(byte, '08b') for byte in byte_data)

def bits_to_bytes(bit_string):
    """Converts a bit string back to bytes."""
    if len(bit_string) % 8 != 0:
        raise ValueError("Bit string length is not a multiple of 8 for byte conversion.")
    # Handle empty string case to avoid error in range
    if not bit_string:
        return b''
    return bytes(int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8))

def embed_data_in_image(image_filepath, data_bits, output_image_filepath):
    """Embeds data bits into the LSB of image pixels."""
    print_verbose(f"Opening original image '{image_filepath}' for embedding base...")
    try:
        img = Image.open(image_filepath).convert("RGBA") # Ensure RGBA
    except FileNotFoundError:
        print(f"[ERROR] Original image file '{image_filepath}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Could not open or process original image '{image_filepath}': {e}")
        sys.exit(1)
    width, height = img.size
    max_bits = width * height * 4 # 4 channels (RGBA)
    print_verbose(f"Original image dimensions: {width}x{height}")
    print_verbose(f"Maximum embeddable bits in this image: {max_bits}")
    print_verbose(f"Total bits to embed (filename len + filename + data len + data): {len(data_bits)}")
    if len(data_bits) > max_bits:
        print(f"[ERROR] Not enough space in the image to embed the data.")
        print(f"       Required: {len(data_bits)} bits, Available: {max_bits} bits.")
        sys.exit(1)
    print_verbose("Embedding data into image pixels (LSB)...")
    img_data = img.load()
    data_iter = iter(data_bits)
    pixels_modified_count = 0
    # Iterate through pixels and channels to embed bits
    for y, x in itertools.product(range(height), range(width)):
        if pixels_modified_count * 4 >= len(data_bits): # Optimization: stop if all bits embedded
             break
        try:
            pixel = list(img_data[x, y])

            for i in range(4): # R, G, B, A channels
                bit_to_embed = next(data_iter, None)
                if bit_to_embed is None: # No more data bits
                    break
                pixel[i] = (pixel[i] & 0xFE) | int(bit_to_embed) # Set LSB
            img_data[x, y] = tuple(pixel)
            if bit_to_embed is not None: # Only count if a pixel was actually modified with data
                pixels_modified_count +=1
            if bit_to_embed is None: # Break outer loop if data ends
                 break
        except Exception as e:
             print(f"[ERROR] Failed during pixel modification at ({x},{y}): {e}")
             sys.exit(1)
    # Final check to ensure all bits were processed
    if next(data_iter, None) is not None:
        print("[WARNING] Not all data bits were embedded. This might indicate an issue.")
    print_verbose(f"Data embedded, modifying approx {pixels_modified_count} pixels.")
    try:
        img.save(output_image_filepath, "PNG")
        print_verbose(f"Steganographic image saved as '{output_image_filepath}'")
    except Exception as e:
        print(f"[ERROR] Failed to save the output image '{output_image_filepath}': {e}")
        sys.exit(1)

def extract_bits_from_image(stego_image_filepath, num_bits_to_extract):
    """
    Extracts a specific number of bits sequentially from the LSB of image pixels.
    Returns the extracted bit string.
    """
    print_verbose(f"Opening steganographic image '{stego_image_filepath}' for extraction...")
    try:
        img = Image.open(stego_image_filepath).convert("RGBA") # Ensure RGBA
    except FileNotFoundError:
        print(f"[ERROR] Steganographic image file '{stego_image_filepath}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Could not open or process steganographic image '{stego_image_filepath}': {e}")
        sys.exit(1)
    width, height = img.size
    max_extractable_bits = width * height * 4
    print_verbose(f"Steganographic image dimensions: {width}x{height}")
    print_verbose(f"Maximum extractable bits from this image: {max_extractable_bits}")
    print_verbose(f"Attempting to extract: {num_bits_to_extract} bits.")
    if num_bits_to_extract > max_extractable_bits:
        print(f"[ERROR] Requested bits to extract ({num_bits_to_extract}) exceeds image capacity ({max_extractable_bits}).")
        print(f"       This might indicate a corrupted image or incorrect metadata.")
        sys.exit(1)
    print_verbose("Extracting data from image pixels (LSB)...")
    img_data = img.load()
    extracted_bits_list = []
    bits_extracted_count = 0
    # Iterate through pixels and channels to extract bits
    for y, x in itertools.product(range(height), range(width)):
        if bits_extracted_count == num_bits_to_extract:
            break
        pixel = img_data[x, y]
        for i in range(4): # R, G, B, A channels
            extracted_bits_list.append(str(pixel[i] & 1)) # Extract LSB
            bits_extracted_count += 1
            if bits_extracted_count == num_bits_to_extract:
                break
    print_verbose(f"Successfully extracted {bits_extracted_count} bits.")
    if bits_extracted_count < num_bits_to_extract:
        # This case should ideally be caught by the check above, but good to have redundancy
        print(f"[ERROR] Expected to extract {num_bits_to_extract} bits, but only got {bits_extracted_count}. Image might be too small or data corrupted.")
        sys.exit(1)
    return "".join(extracted_bits_list)

# --- Main Actions ---
def encrypt_action(data_filepath, original_image_filepath):
    """Encrypts data and its filename, then embeds into an image using original image for key."""
    print_verbose("--- Starting Encryption Process ---")
    # 1. Generate Key from Original Image
    key = generate_key_from_image(original_image_filepath)
    fernet = Fernet(key)
    # 2. Read Data File
    print_verbose(f"Reading data file '{data_filepath}'...")
    try:
        with open(data_filepath, "rb") as f:
            data_bytes = f.read()
        original_filename = os.path.basename(data_filepath) # Get filename
        print_verbose(f"Read {len(data_bytes)} bytes from data file '{original_filename}'.")
    except FileNotFoundError:
        print(f"[ERROR] Data file '{data_filepath}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Could not read data file '{data_filepath}': {e}")
        sys.exit(1)
    # 3. Encrypt Data
    print_verbose("Encrypting data...")
    encrypted_bytes = fernet.encrypt(data_bytes)
    print_verbose(f"Data encrypted to {len(encrypted_bytes)} bytes.")
    # 4. Prepare Filename and Data Bits
    filename_bytes = original_filename.encode('utf-8')
    filename_bits = bytes_to_bits(filename_bytes)
    filename_length_bits = int_to_bits(len(filename_bits), BITS_FOR_FILENAME_LENGTH)
    print_verbose(f"Encoded filename '{original_filename}' to {len(filename_bits)} bits.")
    encrypted_data_bits = bytes_to_bits(encrypted_bytes)
    data_length_bits = int_to_bits(len(encrypted_data_bits), BITS_FOR_DATA_LENGTH)
    print_verbose(f"Encoded encrypted data length ({len(encrypted_data_bits)} bits) using {BITS_FOR_DATA_LENGTH} bits.")
    # 5. Combine all bits: [Filename Length] [Filename] [Data Length] [Data]
    total_bits_to_embed = filename_length_bits + filename_bits + data_length_bits + encrypted_data_bits
    print_verbose(f"Total bits to embed: {len(total_bits_to_embed)} ({BITS_FOR_FILENAME_LENGTH} fn_len + {len(filename_bits)} fn + {BITS_FOR_DATA_LENGTH} data_len + {len(encrypted_data_bits)} data)")
    # 6. Embed into Image
    embed_data_in_image(original_image_filepath, total_bits_to_embed, MIX_IMAGE_FILE)
    print_verbose("--- Encryption Process Complete ---")
    print(f"IMPORTANT: To decrypt, you will need the original image: '{original_image_filepath}'")

def decrypt_action(mix_image_filepath, original_image_filepath):
    """Extracts filename and data from an image, decrypts data using original image key, saves with original filename."""
    print_verbose("--- Starting Decryption Process ---")
    # 1. Generate Key from Original Image
    key = generate_key_from_image(original_image_filepath)
    fernet = Fernet(key)
    # 2. Extract Filename Length from Stego Image
    print_verbose(f"Extracting filename length ({BITS_FOR_FILENAME_LENGTH} bits) from '{mix_image_filepath}'...")
    try:
        # Use a dedicated function for extraction for clarity
        all_extracted_bits_stream = extract_bits_from_image(mix_image_filepath, BITS_FOR_FILENAME_LENGTH) # Start by getting filename length
        filename_length_in_bits = bits_to_int(all_extracted_bits_stream)
        print_verbose(f"Extracted filename length: {filename_length_in_bits} bits.")
        if filename_length_in_bits < 0: # Basic sanity check
             print("[ERROR] Extracted filename length is negative. Cannot proceed.")
             sys.exit(1)
        if filename_length_in_bits % 8 != 0:
             print("[ERROR] Extracted filename length is not a multiple of 8. Likely data corruption.")
             sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] Invalid format during filename length extraction: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to extract filename length: {e}")
        sys.exit(1)
    # 3. Extract Filename Bits
    total_header_bits_needed = BITS_FOR_FILENAME_LENGTH + filename_length_in_bits + BITS_FOR_DATA_LENGTH
    print_verbose(f"Extracting filename ({filename_length_in_bits} bits) and data length ({BITS_FOR_DATA_LENGTH} bits)...")
    try:
        # Extract enough bits for filename length, filename itself, and data length prefix
        header_bits = extract_bits_from_image(mix_image_filepath, total_header_bits_needed)
        # Parse the extracted header bits
        filename_bits = header_bits[BITS_FOR_FILENAME_LENGTH : BITS_FOR_FILENAME_LENGTH + filename_length_in_bits]
        data_length_bits_prefix = header_bits[BITS_FOR_FILENAME_LENGTH + filename_length_in_bits : total_header_bits_needed]
        # Decode filename
        filename_bytes = bits_to_bytes(filename_bits)
        decrypted_filename = filename_bytes.decode('utf-8')
        print_verbose(f"Extracted and decoded filename: '{decrypted_filename}'")
        # Get data length
        encrypted_data_length_in_bits = bits_to_int(data_length_bits_prefix)
        print_verbose(f"Extracted encrypted data length: {encrypted_data_length_in_bits} bits.")
        if encrypted_data_length_in_bits < 0:
            print("[ERROR] Extracted data length is negative. Cannot proceed.")
            sys.exit(1)
    except UnicodeDecodeError:
        print("[ERROR] Failed to decode extracted filename (UTF-8). Data might be corrupted.")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] Invalid format during header extraction/parsing: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to extract or parse header (filename/data length): {e}")
        sys.exit(1)
    # 4. Extract Encrypted Data Bits
    total_bits_to_extract = total_header_bits_needed + encrypted_data_length_in_bits
    print_verbose(f"Extracting total {total_bits_to_extract} bits (header + data) from '{mix_image_filepath}'...")
    try:
        all_extracted_bits = extract_bits_from_image(mix_image_filepath, total_bits_to_extract)
        encrypted_data_bits = all_extracted_bits[total_header_bits_needed:] # Get data bits after the full header

        if len(encrypted_data_bits) != encrypted_data_length_in_bits:
             print(f"[ERROR] Mismatch in expected ({encrypted_data_length_in_bits}) vs extracted ({len(encrypted_data_bits)}) data bits.")
             sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to extract encrypted data bits: {e}")
        sys.exit(1)
    # 5. Convert Encrypted Data Bits to Bytes
    print_verbose("Converting extracted encrypted data bits to bytes...")
    try:
        encrypted_bytes = bits_to_bytes(encrypted_data_bits)
        print_verbose(f"Converted to {len(encrypted_bytes)} encrypted bytes.")
    except ValueError as e:
        print(f"[ERROR] Failed to convert encrypted data bits to bytes: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during encrypted data bit-to-byte conversion: {e}")
        sys.exit(1)
    # 6. Decrypt Data
    print_verbose("Decrypting data...")
    try:
        decrypted_bytes = fernet.decrypt(encrypted_bytes)
        print_verbose(f"Data decrypted successfully ({len(decrypted_bytes)} bytes).")
    except Exception as e:
        print(f"[ERROR] Decryption failed. Ensure the original image '{original_image_filepath}' is correct and unmodified. Error: {e}")
        sys.exit(1)
    # 7. Save Decrypted Data using extracted filename
    output_filepath = decrypted_filename # Use the extracted filename
    print_verbose(f"Saving decrypted data to '{output_filepath}'...")
    try:
        # Prevent accidentally overwriting the script or important files
        if output_filepath == os.path.basename(sys.argv[0]) or output_filepath == original_image_filepath or output_filepath == mix_image_filepath:
             print(f"[ERROR] Decrypted filename '{output_filepath}' matches an input/script file. Aborting to prevent overwrite.")
             sys.exit(1)
        with open(output_filepath, "wb") as f:
            f.write(decrypted_bytes)
        print_verbose("Decrypted data saved successfully.")
    except Exception as e:
        print(f"[ERROR] Could not save decrypted data to '{output_filepath}': {e}")
        sys.exit(1)
    print_verbose("--- Decryption Process Complete ---")

# --- Main Execution ---
def main():
    """Parses arguments and runs the appropriate action."""
    print(f'''
    ████████  ██████     ██████  ██  ██████         ██ ███    ███  ██████  
       ██    ██    ██    ██   ██ ██ ██              ██ ████  ████ ██       
       ██    ██    ██    ██████  ██ ██              ██ ██ ████ ██ ██   ███ 
       ██    ██    ██    ██      ██ ██              ██ ██  ██  ██ ██    ██ 
       ██     ██████  ██ ██      ██  ██████  █████  ██ ██      ██  ██████  
    ''')
    args = sys.argv[1:]
    if len(args) < 3:
        print("Usage:")
        print("  Encrypt: python topic.py <data_file_to_encrypt> <original_image_for_key_and_embedding> encrypt")
        print("  Decrypt: python topic.py <steganographic_image> <original_image_as_key> decrypt")
        print("\nOutputs:")
        print(f"  Encryption: Produces '{MIX_IMAGE_FILE}'")
        print(f"  Decryption: Produces a file named after the originally encrypted file.")
        print("\nIMPORTANT: The <original_image_for_key> must be the EXACT same image file used during encryption for decryption to succeed.")
        sys.exit(1)
    file1 = args[0]
    file2 = args[1]
    action = args[2].lower()
    if action == "encrypt":
        data_filepath = file1
        original_image_filepath = file2
        encrypt_action(data_filepath, original_image_filepath)
    elif action == "decrypt":
        mix_image_filepath = file1
        original_image_filepath_for_key = file2
        # Pass only the required args to decrypt_action
        decrypt_action(mix_image_filepath, original_image_filepath_for_key)
    else:
        print(f"[ERROR] Invalid action: '{action}'. Use 'encrypt' or 'decrypt'.")
        sys.exit(1)

if __name__ == "__main__":
    main()