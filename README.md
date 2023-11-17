# SHA-256-key-and-tag
SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256  

A recreational programming project that provides  

Hash function:                             SHA-256   
Hash-based message authentication tag:     HMAC-SHA-256    
Password-based key derivation function 2:  PBKDF2-HMAC-SHA-256   

Dependencies: NONE

Special properties:    
HMAC & PBKDF2 require scratch buffer memory provided for them (memory use depends on length of inputs).   
Memory buffer requirements:   
HMAC: (64 + data length) bytes   
PBKDF2: (200 + salt length) bytes   

Includes small example program with references to online tests
