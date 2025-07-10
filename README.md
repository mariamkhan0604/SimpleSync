SimpleSync
==========

SimpleSync is a C++-based secure file synchronization system designed to ensure safe and efficient syncing between clients and a central server. It uses SSL/TLS encryption for secure communication and SHA-256 hashing to detect file changes. Each client has its own isolated folder on the server, and the system is capable of syncing only modified or new files.

Features
--------
- Secure communication with SSL encryption (OpenSSL)
- Detects file additions, deletions, and modifications using SHA-256
- File integrity verification after each transfer
- Per-client directory on the server for isolated data storage
- Multithreaded server — handles multiple clients concurrently
- Line-ending normalization for cross-platform hash consistency

Technologies Used
-----------------
- C++17
- OpenSSL (for TLS/SSL)
- POSIX sockets
- std::filesystem, std::thread, unordered_map (C++ STL)
- picosha2 (SHA-256 hashing)

Project Structure
-----------------
<pre> SecureFileSync/ 
├── bin/ # Compiled binaries (client_exec, server_exec) 
├── certs/ # SSL certificate and key 
├── client_hashes/ # Hash logs per client (client-side tracking) 
├── server_data/ # Server-side storage for each client 
├── server_hashes/ # Hash logs per client (server-side tracking) 
├── include/ # Header files 
├── src/ # Source code 
│ ├── client.cpp 
│ ├── server.cpp 
│ └── utils/ 
├── test_files/ # Input directory for client files 
├── Makefile 
├── README.md 
└── .gitignore </pre>


Build Instructions (VSCode Friendly)
------------------------------------
1. Open the folder in VSCode
2. Open the terminal: Ctrl + `
3. Run:

    make clean && make

The binaries will appear in the bin/ directory:
- ./bin/server_exec
- ./bin/client_exec

Dependencies
------------
For Ubuntu/Debian-based systems:

    sudo apt update
    sudo apt install build-essential libssl-dev

Generate SSL Certificates
--------------------------
If certs/ folder is empty, generate a new certificate:

    mkdir -p certs
    openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes

Running the Project
-------------------
Start the Server:

    ./bin/server_exec

Start the Client (in a new terminal):

    ./bin/client_exec cl1

Replace 'cl1' with a unique client ID. Each client gets a dedicated folder in server_data/ and unique hash tracking.

How It Works
------------
1. Client:
   - Computes hashes for all files in test_files/
   - Sends hashes and deleted file list to the server

2. Server:
   - Compares incoming hashes with previous ones
   - Requests only the changed or new files
   - Deletes files that no longer exist on the client side
   - Verifies file integrity using SHA-256 after transfer

Notes
-----
- All client-specific data (files and hashes) is isolated by client ID
- Supports re-synchronization without duplicating unchanged files
- Can run multiple clients in parallel thanks to multithreaded server logic

Example Use Case
----------------
1. Modify or delete any file in test_files/
2. Re-run the client with the same ID
3. The server will:
   - Detect what changed
   - Request only the necessary updates
   - Update the server folder accordingly