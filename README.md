# ToPic - Encrypted data embedding tool


This repository contains two Python scripts for hiding and encrypting data within image files using LSB (Least Significant Bit) steganography.


Two different methods are provided for key generation:


1.  **Password-based Encryption (`topic_pw.py`):** Uses a user-provided password to derive an encryption key.
    
2.  **Image-based Encryption (`topic_img.py`):** Uses the original cover image itself to derive the encryption key.
    


## Features


-   Hide any file within a PNG image.
    
-   Encrypt the hidden data for an extra layer of security.
    
-   Two key derivation methods: password-based and image-based.
    
-   Uses `cryptography` library for strong encryption (Fernet).
    
-   Uses `Pillow` (PIL) for image manipulation.
    


## Prerequisites


-   Python 3.6 or higher
    
-   Pillow (`PIL`)
    
-   cryptography
    


You can install the required libraries using pip:
```
pip install Pillow cryptography
```


## Usage


### 1. Password-based Encryption (`topic_pw.py`)


This script encrypts your data using a password and then embeds it into a cover image.


**Encryption:**
```
python topic_pw.py encrypt <data_file_to_hide> <cover_image.png> -o <output_stego_image.png>
```
-   `<data_file_to_hide>`: The path to the file you want to hide.
    
-   `<cover_image.png>`: The path to the image file that will be used to hide the data.
    
-   `-o <output_stego_image.png>` (Optional): The path to save the resulting steganographic image. If not provided, it defaults to `output.png`.
    


You will be prompted to enter and confirm a password during the encryption process.


*Example:*
```
python topic_pw.py encrypt secret_message.txt nature.png -o hidden_message.png
```


**Decryption:**
```
python topic_pw.py decrypt <stego_image.png>
```


-   `<stego_image.png>`: The path to the steganographic image containing the hidden data.
    


You will be prompted to enter the password used during encryption. The script will extract, decrypt, and save the original file with its original filename.


*Example:*


```
python topic_pw.py decrypt hidden_message.png
```


### 2. Image-based Encryption (`topic_img.py`)
This script encrypts your data using a key derived from the original cover image's content and then embeds it. The original image is **required** for decryption.


**Encryption:**
```
python topic_img.py <data_file_to_hide> <original_cover_image.png> encrypt
```
-   `<data_file_to_hide>`: The path to the file you want to hide.
    
-   `<original_cover_image.png>`: The path to the image file that will be used to hide the data and to derive the encryption key.
    
This command will produce an output steganographic image named `output.png` in the same directory.
*Example:*
```
python topic_img.py sensitive_document.pdf vacation_photo.jpg encrypt
```
**Decryption:**
```
python topic_img.py <stego_image.png> <original_cover_image_used_for_key.png> decrypt
```
-   `<stego_image.png>`: The path to the steganographic image containing the hidden data (`output.png` from the encryption step).
    
-   `<original_cover_image_used_for_key.png>`: The path to the **exact same original image file** that was used during the encryption step. This is crucial for key derivation and successful decryption.
    
The script will extract, decrypt, and save the original file with its original filename.


*Example:*
```
python topic_img.py output.png vacation_photo.jpg decrypt
```


## Important Notes


-   **Data Loss Warning:** **If you forget the password used with `topic_pw.py` or lose/modify the original image used with `topic_img.py`, the hidden and encrypted data will be permanently unrecoverable.** Store your passwords securely and keep a safe, unmodified copy of the original image if using the image-based method.
    
-   **Image Format:** The scripts only works on PNG files since it is lossless, if the image file only has 3 color channels it will convert it to RGBA PNG before embedding to utilize the alpha channel.
    
-   **Image Capacity:** The amount of data you can hide depends on the size of the cover image. Hiding large files requires large images. The scripts include checks for available space.
 
-   **Overwriting Files:** The decryption process attempts to save the extracted file with its original name. Be cautious if a file with the same name already exists in the directory. The scripts include basic checks to prevent overwriting the script or input images.
