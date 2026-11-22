"""Cryptography Suite - algorithms package.

Each module is standalone and owned by one team member so every member can
read, explain, and defend their own algorithms during the oral exam.

Modules:
    member1_alaa.py        - Alaa:        Caesar, Multiplicative, Vernam
    member2_ali2.py        - Ali 2:       Hill, Playfair
    member3_ali_ayman.py   - Ali Ayman:   Affine, DNA
    member4_mohammed_ehab.py - Mohammed Ehab: Vigenere, Autokey
    member5_omar.py        - Omar:        RSA, 14th Algorithm (Atbash)
    member6_amr_elshamy.py - Amr Elshamy: Rail Fence, Single Columnar, Double Columnar

Every algorithm exposes two functions:
    encrypt(text, **params) -> str
    decrypt(text, **params) -> str
and raises ValueError with a friendly message on invalid input/key.
"""
