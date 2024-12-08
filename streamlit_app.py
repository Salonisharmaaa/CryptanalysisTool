import streamlit as st
from collections import Counter
import matplotlib.pyplot as plt
import string
from itertools import permutations
from io import BytesIO
from math import gcd

# Helper Functions

# Caesar Cipher Brute Force
def caesar_brute_force(ciphertext):
    results = []
    for key in range(26):
        decrypted = ''.join(
            chr((ord(char) - key - 65) % 26 + 65) if char.isalpha() else char
            for char in ciphertext.upper()
        )
        results.append((key, decrypted))
    return results

# Affine Cipher Frequency Analysis and Decryption
def affine_frequency_analysis_decrypt(ciphertext):
    # Perform frequency analysis
    counter = Counter([char for char in ciphertext if char.isalpha()])
    total = sum(counter.values())
    frequencies = {char: count / total * 100 for char, count in counter.items()}

    # Plotting the frequencies
    fig, ax = plt.subplots()
    ax.bar(frequencies.keys(), frequencies.values())
    ax.set_title("Letter Frequency Chart")
    ax.set_xlabel("Letters")
    ax.set_ylabel("Frequency (%)")
    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)

    # Most frequent letters in ciphertext
    cipher_most_common = [item[0] for item in counter.most_common(2)]
    # Most frequent letters in English language
    expected_most_common = ['E', 'T']

    # Extended Euclidean Algorithm to find modular inverse
    def extended_euclidean(a, m):
        if gcd(a, m) != 1:
            return None
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1

    # Solve for 'a' and 'b'
    solutions = []
    for i in range(2):
        for j in range(2):
            x1, x2 = ord(cipher_most_common[i]) - 65, ord(cipher_most_common[j]) - 65
            y1, y2 = ord(expected_most_common[i]) - 65, ord(expected_most_common[j]) - 65

            det = x1 - x2
            if det % 26 == 0:
                continue
            det_inv = extended_euclidean(det, 26)
            if det_inv is None:
                continue

            a = (det_inv * (y1 - y2)) % 26
            b = (y1 - a * x1) % 26
            if gcd(a, 26) == 1:
                solutions.append((a, b))

    # Decrypt using first valid (a, b)
    if solutions:
        a, b = solutions[0]
        mod_inverse_a = extended_euclidean(a, 26)
        decrypted = ''.join(
            chr(((mod_inverse_a * (ord(char) - b - 65)) % 26) + 65) if char.isalpha() else char
            for char in ciphertext.upper()
        )
        return buf, a, b, decrypted
    else:
        return buf, None, None, "Unable to solve for a and b."

# Monolalphabetic Cipher Frequency Analysis and Decryption using Chi-Square
def monoalphabetic_frequency_analysis(ciphertext):
    # Perform frequency analysis
    counter = Counter([char for char in ciphertext if char.isalpha()])
    total = sum(counter.values())
    frequencies = {char: count / total * 100 for char, count in counter.items()}

    # Plotting the frequencies
    fig, ax = plt.subplots()
    ax.bar(frequencies.keys(), frequencies.values())
    ax.set_title("Letter Frequency Chart")
    ax.set_xlabel("Letters")
    ax.set_ylabel("Frequency (%)")
    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)

    # Expected English frequencies
    expected_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
        'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
        'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1, 'Z': 0.1
    }

    # Chi-square calculation
    best_match = None
    min_chi_square = float('inf')
    for shift in range(26):
        chi_square = 0
        for char, freq in expected_freq.items():
            observed = frequencies.get(chr((ord(char) - shift - 65) % 26 + 65), 0)
            expected = total * freq / 100
            chi_square += ((observed - expected) ** 2) / expected

        if chi_square < min_chi_square:
            min_chi_square = chi_square
            best_match = shift

    # Decrypt the ciphertext with the best shift
    decrypted = ''.join(
        chr((ord(char) - best_match - 65) % 26 + 65) if char.isalpha() else char
        for char in ciphertext.upper()
    )
    return buf, decrypted

# Vigenère Cipher Key Length Analysis (Kasiski Examination)
def kasiski_examination(ciphertext):
    ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
    sequences = {}
    for i in range(len(ciphertext) - 2):
        seq = ciphertext[i:i + 3]
        if seq in sequences:
            sequences[seq].append(i)
        else:
            sequences[seq] = [i]

    distances = []
    for seq, indices in sequences.items():
        if len(indices) > 1:
            distances.extend(indices[i + 1] - indices[i] for i in range(len(indices) - 1))

    possible_key_lengths = [gcd(*distances) for distances in permutations(distances, 2)] if distances else []
    possible_key_lengths = sorted(set(filter(lambda x: x > 1, possible_key_lengths)))

    return possible_key_lengths

# Vigenère Cipher Decryption
def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    key_length = len(key)
    decrypted = ''
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            decrypted += chr(((ord(char.upper()) - ord(key[i % key_length])) % 26) + 65)
        else:
            decrypted += char
    return decrypted

# Playfair Cipher Decryption
def playfair_decrypt(ciphertext, key):
    key = ''.join(dict.fromkeys(key.upper().replace('J', 'I')))
    key += ''.join([char for char in string.ascii_uppercase if char not in key and char != 'J'])
    matrix = [key[i:i + 5] for i in range(0, 25, 5)]

    def find_position(char):
        for i, row in enumerate(matrix):
            if char in row:
                return i, row.index(char)
        return None

    decrypted = ''
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        row1, col1 = find_position(a)
        row2, col2 = find_position(b)
        if row1 == row2:
            decrypted += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            decrypted += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            decrypted += matrix[row1][col2] + matrix[row2][col1]

    return decrypted

# Streamlit App
def main():
    st.title("Cryptanalysis Tool")

    # Cipher Selection
    cipher = st.selectbox("Select Cipher:", ["Caesar Cipher", "Affine Cipher", "Monolalphabetic Cipher", "Vigenère Cipher", "Playfair Cipher"])

    # Input for Ciphertext
    ciphertext = st.text_area("Enter Ciphertext:")

    if st.button("Analyze"):
        if not ciphertext:
            st.warning("Please provide ciphertext.")
            return

        if cipher == "Caesar Cipher":
            results = caesar_brute_force(ciphertext)
            st.subheader("Brute Force Results")
            for key, decrypted in results:
                st.write(f"Key {key}: {decrypted}")

        elif cipher == "Affine Cipher":
            buf, a, b, decrypted = affine_frequency_analysis_decrypt(ciphertext)
            st.subheader("Frequency Analysis")
            st.image(buf, caption="Frequency Chart", use_column_width=True)
            if a and b:
                st.subheader("Decryption")
                st.write(f"Key Values: a = {a}, b = {b}")
                st.write(f"Decrypted Message: {decrypted}")
            else:
                st.error(decrypted)

        elif cipher == "Monolalphabetic Cipher":
            st.subheader("Frequency Analysis")
            buf, decrypted = monoalphabetic_frequency_analysis(ciphertext)
            st.image(buf, caption="Frequency Chart", use_column_width=True)
            st.subheader("Expected Decrypted Message")
            st.write(decrypted)

        elif cipher == "Vigenère Cipher":
            st.subheader("Kasiski Examination")
            possible_lengths = kasiski_examination(ciphertext)
            if possible_lengths:
                st.write(f"Possible Key Lengths: {possible_lengths}")
            else:
                st.write("No repeated sequences found for key length determination.")

            # Input for the key
            key = st.text_input("Enter Key for Decryption:", key="vigenere_key")

            # Check if the key is provided and decrypt
            if key:
                if not key.isalpha():
                    st.error("The key must contain only alphabetic characters.")
                else:
                    decrypted = vigenere_decrypt(ciphertext, key)
                    st.subheader("Decrypted Message")
                    st.write(decrypted)
            else:
                st.info("Please enter a valid key to decrypt the ciphertext.")



        elif cipher == "Playfair Cipher":
            key = st.text_input("Enter Key for Decryption:")
            if key:
                decrypted = playfair_decrypt(ciphertext, key)
                st.subheader("Decrypted Message")
                st.write(decrypted)

if __name__ == "__main__":
    main()
