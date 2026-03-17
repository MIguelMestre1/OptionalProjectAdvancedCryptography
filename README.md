# Optional Project: Advanced Cryptography - Secure UDP Video Stream


## 📖 Project Description

This project implements a secure, real-time video streaming architecture using Java. It consists of two main components:
1. **SecureStreamServer**: Reads a real-time sequence of MP4 frames from a `.dat` movie file, encrypts the payload frame-by-frame, and streams it over UDP.
2. **SecureUDPproxy**: Acts as a transparent local proxy. It listens for the encrypted UDP packets sent by the server, decrypts them in real-time, and forwards the plaintext stream to a local delivery port where a media player (like VLC or MPV) can play the video.

### Supported Encryption Algorithms
The project implements three cryptographic approaches to secure the stream:
* **`AES`**: Uses `AES/GCM/NoPadding` (Authenticated Encryption with Associated Data) with a 128-bit key and random 12-byte IVs.
* **`CHACHA`**: Uses the `ChaCha20-Poly1305` stream cipher with a 256-bit key and random 12-byte IVs.
* **`CUSTOM`**: A custom-built Pseudo-Random Function (PRF) key generator using `SHA-256` hashing and `AES/ECB/NoPadding`. It generates an extended key that is XORed against the video payload frame by frame.

---

## Prerequisites and Dependencies

To build and run this project, you will need:
* **Java Development Kit (JDK):** Version 8 or higher.
* **Media Player:** [VLC Media Player](https://www.videolan.org/) or [MPV](https://mpv.io/) to play the output stream.
* **Video File:** A correctly formatted `.dat` movie file containing the MP4 frame sequence (expected by the server's byte-reading logic).

---

## Build & Configuration Instructions


### 1. Compilation
Navigate to the repository folder in your terminal and compile the Java source files:
```bash
javac SecureStreamServer.java SecureUDPproxy.java
```
### 2. Execution

1. **Navigate vlc and initialize Network stream in udp://@:7777**
2. **run SecureUDPproxy** 
```bash
java SecureUDPproxy.java <encryptionMethod>
```
3.  **run SecureStreamServer**
```bash
:java SecureStreamServer.java movies/<movie>.dat <remote_ip> <remote_port> <encryptionMethod>
```





