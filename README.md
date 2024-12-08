# Cryptanalysis Tool
An interactive cryptanalysis tool built using Python and Streamlit that allows users to analyze and decrypt ciphertexts encrypted with different classical ciphers. This tool is especially useful for educational purposes, providing both frequency analysis and decryption capabilities.

# Features
## Supported Ciphers:
### Caesar Cipher:
Brute force all possible keys and display decrypted messages.

### Affine Cipher:
1. Perform frequency analysis and display a frequency chart.

2. Use the two most frequent letters to solve equations and determine keys a and b.

3. Decrypt and display the message with the determined keys.

### Monolalphabetic Cipher:
1. Perform frequency analysis and display a frequency chart.

2. Use Chi-square analysis to identify the best possible decryption and display it.

### Vigenère Cipher:
1. Perform Kasiski examination to suggest possible key lengths.

2. Allow the user to input a key for decryption and display the decrypted message.

### Playfair Cipher:
1. Allow the user to input a key and decrypt the message based on the Playfair cipher rules.
   
# Installation

## Prerequisites
1. Ensure you have Python installed (version 3.7 or later). Install Streamlit and other dependencies:
2. pip install streamlit matplotlib

## Clone the Repository
```
git clone https://github.com/yourusername/cryptanalysis-tool.git cd cryptanalysis-tool
```

# Usage
## Run the Application
1. To start the Streamlit app, run:
```
streamlit run cryptanalysis_tool.py
```

# Instructions

1. Select a cipher from the dropdown menu.

2. Enter the ciphertext in the provided text area.

3. For certain ciphers, additional inputs like keys may be required.
