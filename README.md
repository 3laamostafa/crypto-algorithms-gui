# Cryptography Suite — Security Workbench

A desktop cryptography workbench built with **Python** and **CustomTkinter**, separating the graphical user interface (`main.py`) from the cryptographic algorithm implementations (`algorithms/`) so each team member can maintain and explain their assigned ciphers.

## Project Structure

    coffe/
    ├── main.py
    ├── requirements.txt
    └── algorithms/
        ├── __init__.py
        ├── member1_alaa.py
        ├── member2_ali2.py
        ├── member3_ali_ayman.py
        ├── member4_mohammed_ehab.py
        ├── member5_omar.py
        └── member6_amr_elshamy.py

## Included Algorithms & Team Ownership

| Member | Algorithms |
| :--- | :--- |
| **Alaa Mostafa Zedan (Member 1)** | Caesar Cipher, Multiplicative Cipher, Vernam Cipher |
| **Ali 2 (Member 2)** | Hill Cipher, Playfair Cipher |
| **Ali Ayman (Member 3)** | Affine Cipher, DNA Encryption |
| **Mohammed Ehab (Member 4)** | Vigenere Cipher, Autokey Cipher |
| **Omar (Member 5)** | RSA, Rail Fence Transposition |
| **Amr Elshamy (Member 6)** | Single Columnar Transposition, Double Columnar Transposition |

## Setup & Run

    cd coffe
    pip install -r requirements.txt
    python main.py

## Features

- Category grouping and live search filtering in the sidebar.
- Dynamic key inputs, mathematical formulas, and usage guides per algorithm.
- Encryption, decryption, output-to-input swap, clipboard copy, clear, and sample input loading.
- RSA key generation from prime numbers `p` and `q` with public `(e, n)` and private `(d, n)` key display.
