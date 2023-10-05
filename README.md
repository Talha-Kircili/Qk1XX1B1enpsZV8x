# Methodology

## 1. Phase: Investigating the [technology page](https://security-challenge.bmw-carit.de/fabulousmobility/technology)
- "all our data is encrypted using state-of-the-art AES-256-CBC cryptography"

  &#8594; assuming the challenge is about a padding oracle attack, because the block cipher mode being used is CBC and the puzzle title says "Crypto with Oracles"

## 2. Phase: Evaluating the Assumption

- manipulating one byte at a time of the cookie and sending it back to the server

- getting various error messages (see below)  
  &#8594; "AES-256-CBC Decoding Error - The decrypted message fragment has invalid PKCS7 padding and cannot be decoded"  
  &#8594; side-channel for a padding oracle attack

## Summary of all the informations gathered

- server uses AES-256-CBC to encrypt cookies
- some cookie values return an invalid padding error
- same error message includes the padding method in use: PKCS7 Padding

  &#8594; server vulnerable to a padding oracle attack - adversary can decrypt the ciphertexts and create for any plaintext the corresponding ciphertext
- the vulnerability lays behind the CBC Malleability:  
  Every block uses the previous block as an IV, which does get XORed with the plaintext (Encryption) or decrypted ciphertext (Decryption)  
  &#8594; not random, can be abused to manipulate the plaintext

## 3. Phase: Scripting the padding oracle attack

1. base64 decode cookie
2. divide it into blocks of ciphertext: each block contains 16 bytes, because of the block length of AES 
3. generate random IV'
4. base64 encode it together with a block of ciphertext
5. send it to the server and check for the response
6. if the response is "AES-256-CBC Decoding Error", then the padding is invalid  
   &#8594; increment the byte you want to decrypt and repeat steps 4.-6. until this error does not appear
7. manipulating the last byte and not getting an decoding error message means, that the plaintext contains the padding byte 01 (for the second last byte, the padding byte is 02 02 etc.)
8. xor last byte of IV' together with the padding byte 01 &#8594; we now have the decrypted ciphertext byte - not the plaintext
9. in order to obtain the plaintext, we have to xor the decrypted ciphertext byte with the original IV
10. for the next plaintext bytes, the bytes of the random IV, which already decrypted certain ciphertext bytes, do get manipulated in the following way:
  IV'' = decrypted byte XOR new padding byte
11. with this new IV'', repeat the steps 4.-10.
12. repeat every step above for each and every block

# First Flag: Obtaining the secret customer token

Flag: **CIT-5adc6a7fa896ba1155347e74c4e15c105759b760464c73a3089f39a3dd470997**

# Second Flag: Accessing restricted information

Flag: **CIT-02f71f19ef44eea91675beb288d972a37265e751dffa9d76b9f3e613430ad72b**

# Interesting Cookie Values
## Django Error 
4yb/uLGJU4tYlMSFDoBLoggB01wC6uEYVMk8/KDcXSTkiaGDCD5zp0XOQgpDoR0r8m6u1FQJBtufnHSNFVdANJao2Ep4TzadqLbP74wpLiQ6+8C+TWE6jdNVmweSe7RMTG8z1iDugmQ5SRnWs2K/XAKhNARwM9CJqMdW/zOP9Qo=
  
## AES-256-CBC Decoding Error  
5yb/uLGJU5tYlMSFDoDLoggB01wC6uFYVMk8/KEcXSTkiaGDCD6zp0XOQgpDoR2r8m6u1FQJBtufnHSNFVdANJao3Ep4TzadqLbP74wpLiQ6+8C+TWE7jdNVmweSe7RMTG8z1iDugmQ5SRnWs2K/XAKhOARwM9CJqMdW/zOP9Ro=
