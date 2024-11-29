# Cryptography
Explanation:
1. Key Exchange:
The system employs Diffie-Hellman for secure key exchange. This provides a method for two parties to agree on a shared secret over an insecure channel. The use of Diffie-Hellman ensures that the shared secret is not exposed to potential eavesdroppers.

2. Encryption (AES in CBC Mode):
AES is used for symmetric encryption, providing confidentiality. The choice of AES with a 128-bit key length is common and strikes a balance between security and performance.
CBC mode is chosen for encryption. It provides a good level of security and is suitable for securing block-based data.

3. Hashing:
SHA-256 is used for hashing the shared secret. SHA-256 is widely accepted and provides a strong, fixed-size representation of the shared secret.
The code also hashes the initial message, providing a hash for verification and ensuring the integrity of the original message.

4. Initialization Vector (IV):
A random IV is generated for each encryption operation in CBC mode, enhancing the security of the encryption process.
The IV is shared between parties to enable the decryption process.

5. Error Handling:
The system incorporates an error-handling mechanism through the handleErrors function. It prints error messages and exits the program in case of failures, contributing to robustness.

6. Output Display:
The system provides informative output, including the hashed shared secret, ciphertext, and decrypted plaintext. This aids in understanding and verifying the cryptographic processes.
