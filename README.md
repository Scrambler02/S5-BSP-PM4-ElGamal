# S5-BSP-PM4-ElGamal
Secure communication often assumes that both sender and receiver can freely exchange messages without interference. In practice, this is not always the case: messages can be intercepted, altered, or observed by third parties such as service providers, network administrators, or more malicious parties. Standard encryption schemes protect the contents of the message, but often do not hide the presence of the communication itself.
Anamorphic encryption deals with this limitation by allowing one single ciphertext to encode two messages. Depending on which decryption key is used, a different message can be revealed. This allows for plausible deniability, since any intercepted key only reveals an innocent cover message, while the secret message remains hidden.
ElGamal encryption is perfectly suitable for this, because its random-looking outputs allow for a hidden message be embedded without altering the appearance of the ciphertext. Therefore, by combining pseudorandom generation with careful key handling, multiple messages can be hidden in a single ciphertext.
This paper presents a new ElGamal-based anamorphic encryption scheme implemented in Pixel Mask 4.0. 
The updated system is faster and more robust than earlier versions, making anamorphic cryptography easy to use for secure communication through Pixel Mask.

## Code structure

- **PM4.py:** Main application launch file
- **password_manager.py:** Displays login window and sets, loads, and verifies password
- **ElGamal_testing.ipynb:** Contains all testing of ElGamal and BSGS
- **ame_code folder:** Contains ElGamal AME and char-int mapping code
- **crypt_code folder:** Contains encryption and decryption code for steganography
- **stego_code folder:** Contains LSB and DCT steganography code
- **ui_code folder:** Contains text for PM help and explanation commands
- **assets folder:** Contains Echo sprites for every mode

## Running Pixel Mask 4.0

Just run the PM4.py file.