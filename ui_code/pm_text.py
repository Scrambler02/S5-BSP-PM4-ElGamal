# Pixel Mask 4.0 - Output Texts

# ------- DEFAULT TEXTS ------- #

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


# ------- AME TEXTS ------- #

ame_cmd_txt = """#PM: Below are all possible options for ame commands:
   ame mode\n   ame commands\n   ame\n   ame help\n   mode?\n   about\n   create keys\n   load pk\n   load sk   
   load ska\n   encrypt\n   decrypt\n   ame decrypt\n   cancel\n   clear\n   exit\n
"""

ame_text = """Anamorphic encryption is a technique that allows two different messages to be embedded
   in a single ciphertext, where different keys reveal different messages.
   This application implements a custom anamorphic encryption scheme based on
   ElGamal-style public-key cryptography and symmetric state parameters.
   WARNING: Only works on messages containing words < 7 characters long.

   How does it work?
   • The receiver begins by creating a set of AME keys
      ◦ A public key (pk) - for encryption
      ◦ A secret key (sk) - to reveal the decoy message
      ◦ A double key (ska) - to reveal the secret message

   • The public key can be shared openly
      ◦ It does not reveal either message on its own

   • The sender loads the public key and starts encryption
      ◦ First, a decoy message is entered
      ◦ Then, a secret message is entered

   • The application generates:
      ◦ A single ciphertext containing both messages
      ◦ An initialization value (IV)
      ◦ A state value (ST) used during encryption

   • The ciphertext, IV, and initial ST are saved to a file
      ◦ This file can be shared openly

   • Decryption depends on which key is used:
      ◦ Using the secret key (sk) reveals the decoy message
      ◦ Using the double key (ska) reveals the secret message

   • The receiver chooses how to decrypt:
      ◦ “decrypt” reveals the decoy message
      ◦ “ame decrypt” reveals the secret message

   This allows a harmless-looking message to be revealed under coercion,
   while a different key exposes the true hidden message.
"""


ame_help = """
   1. Receiver:
      • Enter 'create keys' to generate:
         ◦ Public key (pk)
         ◦ Secret key (sk)
         ◦ Double key (ska)
      • All keys are saved to the ame_keys folder on your desktop
         ◦ public_key.txt
         ◦ secret_key.txt
         ◦ double_key.txt
      • Share the public key with the sender
         ◦ Can be done openly
      • Keep the secret key and double key secure

   2. Sender:
      • Enter 'load pk' to load the receiver's public key
      • Enter 'encrypt' to start AME encryption:
         ◦ Enter the decoy message
         ◦ Enter the secret message
      • The application generates:
         ◦ A single ciphertext containing both messages
         ◦ An initialization value (IV)
         ◦ A state value (ST)
      • The ciphertext, IV, and initial ST are saved to a file:
         ◦ ct.txt in the ciphertext folder on your desktop
      • Send the ciphertext file to the receiver

   3. Receiver:
      • Load the appropriate key:
         ◦ Enter 'load sk' to load the secret key (decoy message)
         ◦ Enter 'load ska' to load the double key (secret message)
      • Enter 'decrypt' to reveal the decoy message
         ◦ Uses the secret key (sk)
      • Enter 'ame decrypt' to reveal the secret message
         ◦ Uses the double key (sk_a)
"""
