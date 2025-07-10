SimpleSync
==============

SimpleSync is a C++-based secure file synchronization system that uses SSL for encrypted communication and SHA-256 hashing for change detection. Each client has a dedicated folder on the server. The system ensures efficient file synchronization and integrity verification.

Features
--------
- SSL-encrypted communication using OpenSSL
- SHA-256 hash-based file change detection
- Automatic detection of file additions, deletions, and modifications
- Per-client directory isolation on the server
- File integrity verification after transfer
- Multithreaded server handling multiple clients
- Line-ending normalization for consistent hashing

Technologies Used
-----------------
- C++17
- POSIX sockets
- OpenSSL
- Standard Library (filesystem, thread, etc.)
- picosha2 (SHA-256 hashing utility)

Directory Structure
-------------------
SecureFileSync/
├── bin/               # Compiled binaries (client_exec, server_exec)
├── certs/             # SSL certificate and key
├── client_hashes/     # Hash logs per client (client-side tracking)
├── server_data/       # Server-side storage for each client
├── server_hashes/     # Hash logs per client (server-side tracking)
├── include/           # Header files
├── src/               # Source code
│   ├── client.cpp
│   ├── server.cpp
│   └── utils/
├── test_files/        # Input directory for client files
├── Makefile
├── README.md
└── .gitignore

Build the Project (VSCode Friendly)
-----------------------------------
1. Open the project folder in VSCode.
2. Open terminal: Ctrl + `
3. Run:
   make clean && make

The compiled binaries will be created in the bin/ directory:
- bin/server_exec
- bin/client_exec

Dependencies (Ubuntu/Debian)
----------------------------
sudo apt update
sudo apt install build-essential libssl-dev

Generate SSL Certificates
-------------------------
If not already present, run:

mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes

Running the Project
-------------------
1. Start the Server:
   ./bin/server_exec

2. Run the Client in another terminal:
   ./bin/client_exec cl1

Replace 'cl1' with a unique ID for each client.

How It Works
------------
- The client computes SHA-256 hashes for files in test_files/
- Sends hashes and deletion list to the server
- Server compares and requests only new/modified files
- Server deletes missing files
- Client sends requested files
- Server verifies integrity via SHA-256
