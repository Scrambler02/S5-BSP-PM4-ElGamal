# Pixel Mask 4.0 - Output Texts

# ======== DEFAULT TEXTS ======== #


about_info = """Pixel Mask\n   Version 3.0\n   Written in Python version 3.12.3
   Developed by Peter Roenne and Kim Tereba\n   Uni.lu"""

cmd_txt = """#PM: Below are all possible options for commands:
   commands\n   about\n   stego\n   stego help\n   mode?\n   create key\n   load key\n   encrypt
   decrypt\n   2jpg\n   lsb mask\n   lsb unmask\n   dct mask\n   dct unmask\n   ame mode\n   light mode\n   dark mode   
   blue mode\n   red mode\n   cancel\n   clear\n
"""

stego_text = """Steganography is the practice of making information undetectable by hiding it in plain sight.
   This application uses AES encryption, LSB and DCT steganography to hide messages in images and NumPy files.

   How does it work?
   • Begin by creating a key with a secret value that you need to remember
   • Save the key to any folder of your choosing
   • The key is used to embed your secret message into a chosen cover image
   • Load the key from the saved folder

   • LSB steganography:
      ◦ Provide the image (JPG format) and message, the stego image (PNG format) is returned
      ◦ It's saved to a folder titled 'img' on the desktop and now contains the hidden message

   • DCT steganography:
      ◦ Provide the image (JPG format) and message, the NumPy file is returned
      ◦ It's saved to a folder titled 'file' on the desktop and now contains the hidden message

   • The stego image or NumPy file can be sent to another person via lossless telecommunication 
     channels, such as email
   • Share the secret value used to create the original key with the recipient for them to generate 
     the same key
   • With the stego image/file and key, the recipient can extract and decrypt the hidden message
   • To see the specific instructions on how to use this application enter 'help'"""

stego_help = """
   1. Creating a key:
      • Enter 'create key'
      • Enter any secret value for key creation
      • Key is returned to a folder of your choosing as key.txt file
   2. Loading the key:
      • Enter 'load key'
      • Enter folder name containing the key, 'Desktop' works too
   3. Embedding a message into image:
      • Enter 'lsb mask' or 'dct mask' command
      • Choose the cover image
      • Ensure the image is in JPG format
          ◦ Use '2jpg' command for PNG -> JPG image conversion
      • Stego image or file is returned to desktop in 'LSB_img' or 'DCT_file' folder
   4. Extracting a message from stego image or file
      • Key from same secret value is required for decryption
      • Enter 'lsb unmask' or 'dct unmask' command
      • Choose the stego image or file
      • The secret message is returned
      • To cancel any of these operations enter 'cancel'\n"""


# ======== AME TEXTS ======== #


ame_cmd_txt = """#PM: Below are all possible options for ame commands:
   ame mode\n   ame commands\n   ame\n   ame help\n   mode?\n   about\n   create keys\n   load pk\n   load sk\n   encrypt
   load k\n   load dk\n   decrypt\n   ame decrypt\n   cancel\n   clear\n   exit\n
"""

ame_text = """The anamorphic encryption technique is a method of embedding two messages in one ciphertext,
   such that two different decryption keys reveal two different messages. 
   This application uses RSA and mathematical operations for a hybrid encryption scheme, inspired by 
   anamorphic encryption but not following the standard protocol.

   How does it work?
   • The receiver begins by creating public and private RSA keys
      ◦ The public key will be used by the sender to wrap (encrypt) the anamorphic keys
      ◦ The private key will be used later by the receiver to unwrap (decrypt) them

   • The receiver shares the public key with the sender
      ◦ Can be done openly since public key doesn't reveal any messages

   • The sender loads the public key and then encrypts two messages:
      ◦ Cover message
      ◦ Secret message

   • The application returns a ciphertext and two anamorphic keys:
      ◦ Key1 reveals the cover message
      ◦ Key2 reveals the secret message
      ◦ Both are wrapped using the receiver's public key

   • The sender shares the ciphertext and Key1 with the receiver
      ◦ Key1 can be shared openly or securely, since it only reveals the cover message
      ◦ Key2 must be shared securely (e.g. via Signal), because it unlocks the secret message

   • The receiver unwraps the keys using their private key
      ◦ Uses Key1 to read the cover message or Key2 to read the secret message
"""

ame_help = """
1. Receiver:
   • Enter 'create keys' to generate:
       ◦ RSA public key
       ◦ RSA private key
       ◦ Both are saved to rsa_keys folder on desktop
   • Share the public key with sender
       ◦ Can be done openly
   • Keep the private key secure

2. Sender:
   • Enter 'load pk' to use the receiver's public key
   • Enter 'encrypt' to encode two messages:
       ◦ Enter the cover message
       ◦ Enter the secret message
   • This returns the ciphertext and two AME keys:
       ◦ Wrapped Key1 as k.txt file (for cover message)
       ◦ Wrapped Key2 as dk.txt file (for secret message)
       ◦ Both are saved to ame_keys folder on desktop
   • Send ciphertext + Key1 + Key2 to the receiver
       ◦ Key1 can be shared openly
       ◦ Key2 must be shared securely (e.g. via Signal)

3. Receiver:
   • Enter 'load sk' to load your private key
   • Enter 'load k' and 'load dk' to load the wrapped AME keys
       ◦ During decryption the private key will unwrap both keys
   • Enter 'decrypt' to read the cover message:
       ◦ Enter ciphertext + provide Key1
   • Enter 'ame decrypt' to read the secret message:
       ◦ Enter ciphertext + provide Key2
"""
