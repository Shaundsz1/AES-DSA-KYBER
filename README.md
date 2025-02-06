# Lab 1 - **SHAUN DSOUZA** Submission
# MODULE 1
# 1.Setup OpenSSL:
I created a sub-module for OpenSSL within my lab directory to handle the cryptographic operations efficiently.

# 2.Python Setup for Plotting Timing Distributions
Used Python for plotting the timing distributions. I installed Python using the following commands:
# sudo apt update
# sudo apt install python-is-python3

# 3. Generating Timing Data
I used a Makefile to automate the testing and timing processes. By running the following command, I generated timing data for each encryption method AES, RSA, and Kyber:
make p1
This Created Three .txt files which had the time stamps each .txt file logs the time taken for encrypting the data multiple times
# 4. Plotting the Timing Distribution
To see the performance differences between AES, RSA, and Kyber, I used Python's matplotlib library.
python3 plot_timings.py
# 5. Cleaning Up

# MODULE 2
For this module, I encrypted a .PPM image using two different AES modes: ECB and CBC. The image file was first separated into two parts: the header and the body. This allowed me to encrypt only the image data (body) while leaving the header intact for proper reconstruction
# head -n 3 penguin.PPM > header.txt
# tail -n +4 penguin.PPM > body.bin

# 2. Encrypting the Body Using AES-128-ECB
# openssl enc -aes-128-ecb -nosalt -pass pass:"A" -in body.bin -out enc_body.bin
This generated the encrypted body (enc_body.bin), which would later be combined with the original header to reconstruct the image.

# 3. Reconstructing the ECB-Encrypted Image
To reconstruct the image, I concatenated the unencrypted header with the encrypted body:
# cat header.txt enc_body.bin > ecb_penguin.ppm

# 4. Encrypting the Body Using AES-128-CBC
Next, I encrypted the body of the image using AES in CBC mode (Cipher Block Chaining)
# openssl enc -aes-128-cbc -nosalt -pass pass:"A" -in body.bin -out enc_body.bin

# 5. Reconstructing the CBC-Encrypted Image
As before, I reconstructed the image by concatenating the header with the encrypted body:
# cat header.txt enc_body.bin > cbc_penguin.ppm

# Module 3 
# 1. RSA Key Generation
Generated the Public Key and the Private Key The server requires the RSA key pair for secure key exchange with the client.
# openssl genrsa -out private.pem 2048
# openssl rsa -in private.pem -outform PEM -pubout -out public.pem

# 2.Secure Communication Protocol with RSA:
I implemented a client-server protocol where RSA was used for public key encryption to securely exchange an AES key.
# 3.Debugging and Testing the Client Code
Encrypted and decrypted the message using AES.
# 4.Created Makefile Using OpenSSL
Specified the OpenSSL library paths for RSA and AES functionalities.
# 5.Set the Target in Makefile 
# Make p3 

# MODULE 3: QUANTUM SECURE COMMUNICATION WITH KYBER and AES
Quantum Secure Communication Protocol with Kyber:
In this option, I implemented quantum-safe communication using Kyber for key encapsulation and AES for message encryption. 

Makefile Integration for Kyber:
I added rules to the Makefile for handling Kyber-based communication. By running the make p3 command, I initiated the Kyber-based communication:
# Make p3

Please put your single PDF write up and codes here, and change your name in the line above. Please make sure everything works and instructions are clear. Make sure your makefile creates all dependent files.