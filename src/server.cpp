// #include <iostream>
// #include <cstring>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <unistd.h>
// #include <sstream>
// #include <unordered_map>
// #include <fstream>
// #include <vector>
// #include <filesystem>
// #include "../include/sha256.h"

// #define PORT 8080
// #define BUFFER_SIZE 4096

// std::unordered_map<std::string, std::string> parseSerializedData(const std::string& data) {
//     std::unordered_map<std::string, std::string> result;
//     std::istringstream stream(data);
//     std::string line;

//     while (std::getline(stream, line)) {
//         size_t delimiterPos = line.find('|');
//         if (delimiterPos != std::string::npos) {
//             std::string path = line.substr(0, delimiterPos);
//             std::string hash = line.substr(delimiterPos + 1);
//             std::string normalized = std::filesystem::path(path).lexically_normal().string();
//             std::cout << "🔍 Parsed: '" << path << "' -> '" << normalized << "' => " << hash << "\n";
//             result[normalized] = hash;
//         }
//     }

//     return result;
// }

// int main() {
//     int server_fd, new_socket;
//     struct sockaddr_in address;
//     int opt = 1;
//     int addrlen = sizeof(address);
//     char buffer[BUFFER_SIZE] = {0};

//     server_fd = socket(AF_INET, SOCK_STREAM, 0);
//     if (server_fd == 0) {
//         std::cerr << "❌ Socket failed\n";
//         return -1;
//     }

//     setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
//     address.sin_family = AF_INET;
//     address.sin_addr.s_addr = INADDR_ANY;
//     address.sin_port = htons(PORT);

//     if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
//         std::cerr << "❌ Bind failed\n";
//         return -1;
//     }

//     if (listen(server_fd, 3) < 0) {
//         std::cerr << "❌ Listen failed\n";
//         return -1;
//     }

//     std::cout << "🟢 Server listening on port " << PORT << "...\n";

//     new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
//     if (new_socket < 0) {
//         std::cerr << "❌ Accept failed\n";
//         return -1;
//     }

//     std::cout << "🔗 Client connected!\n";

//     // 1. Greeting
//     const char* greeting = "Hello from server!";
//     send(new_socket, greeting, strlen(greeting), 0);

//     // 2. Receive file hashes
//     int dataSize = 0;
//     read(new_socket, &dataSize, sizeof(dataSize));

//     std::string receivedData;
//     int totalRead = 0;
//     while (totalRead < dataSize) {
//         int bytesRead = read(new_socket, buffer, std::min(BUFFER_SIZE, dataSize - totalRead));
//         if (bytesRead <= 0) break;
//         receivedData.append(buffer, bytesRead);
//         totalRead += bytesRead;
//     }

//     std::unordered_map<std::string, std::string> clientHashes = parseSerializedData(receivedData);

//     // 3. Receive deleted file list
//     int numDeleted = 0;
//     read(new_socket, &numDeleted, sizeof(numDeleted));

//     std::vector<std::string> deletedFiles;
//     for (int i = 0; i < numDeleted; ++i) {
//         int pathLen = 0;
//         read(new_socket, &pathLen, sizeof(pathLen));
//         std::vector<char> delBuf(pathLen);
//         read(new_socket, delBuf.data(), pathLen);
//         std::string delPath(delBuf.begin(), delBuf.end());
//         deletedFiles.push_back(std::filesystem::path(delPath).lexically_normal().string());
//     }

//     // ✅ 4. Delete files from server
//     for (const std::string& deletedPath : deletedFiles) {
//         std::string fullPath = "server_data/" + deletedPath;
//         std::filesystem::path normalized = std::filesystem::path(fullPath).lexically_normal();
//         std::cout << "🗑️ Attempting to delete: " << normalized << "\n";

//         try {
//             if (std::filesystem::exists(normalized)) {
//                 bool removed = std::filesystem::remove(normalized);
//                 if (removed) {
//                     std::cout << "✅ Deleted: " << normalized << "\n";
//                 } else {
//                     std::cout << "⚠️ File exists but not removed: " << normalized << "\n";
//                 }
//             } else {
//                 std::cout << "⚠️ File not found: " << normalized << "\n";
//             }
//         } catch (const std::filesystem::filesystem_error& e) {
//             std::cerr << "❌ Error deleting " << normalized << ": " << e.what() << "\n";
//         }
//     }

//     // 5. Read previous hash snapshot
//     std::unordered_map<std::string, std::string> oldHashes;
//     std::ifstream infile("previous_hashes.txt");
//     std::string line;
//     while (std::getline(infile, line)) {
//         size_t delimiterPos = line.find('|');
//         if (delimiterPos != std::string::npos) {
//             std::string path = std::filesystem::path(line.substr(0, delimiterPos)).lexically_normal().string();
//             std::string hash = line.substr(delimiterPos + 1);
//             oldHashes[path] = hash;
//         }
//     }
//     infile.close();

//     // 6. Compare and detect changes
//     std::cout << "\n🔍 Change Detection:\n";
//     for (const auto& [path, hash] : clientHashes) {
//         if (oldHashes.count(path)) {
//             if (oldHashes[path] == hash)
//                 std::cout << "✅ Unchanged: " << path << "\n";
//             else
//                 std::cout << "✏️ Modified: " << path << "\n";
//         } else {
//             std::cout << "🆕 New File: " << path << "\n";
//         }
//     }
//     for (const auto& [path, _] : oldHashes) {
//         if (!clientHashes.count(path)) {
//             std::cout << "❌ Deleted File: " << path << "\n";
//         }
//     }

//     // 7. Save updated hash list
//     std::ofstream outfile("previous_hashes.txt");
//     for (const auto& [path, hash] : clientHashes) {
//         outfile << path << "|" << hash << "\n";
//     }
//     outfile.close();

//     // 8. Decide which files to request
//     std::vector<std::string> filesToRequest;
//     for (const auto& [path, hash] : clientHashes) {
//         if (!oldHashes.count(path) || oldHashes[path] != hash) {
//             filesToRequest.push_back(path);
//         }
//     }

//     // 9. Request files
//     std::string requestMessage;
//     for (const std::string& filePath : filesToRequest) {
//         requestMessage += filePath + "\n";
//     }

//     int numFiles = filesToRequest.size();
//     send(new_socket, &numFiles, sizeof(numFiles), 0);
//     int msgLength = requestMessage.size();
//     send(new_socket, &msgLength, sizeof(msgLength), 0);
//     send(new_socket, requestMessage.c_str(), msgLength, 0);

//     std::cout << "📤 Requested " << numFiles << " file(s) from client\n";

//     // 10. Receive files
//     for (int i = 0; i < numFiles; ++i) {
//         int pathLen = 0;
//         if (read(new_socket, &pathLen, sizeof(pathLen)) <= 0 || pathLen <= 0) {
//             std::cerr << "❌ Invalid path length received, skipping...\n";
//             continue;
//         }

//         std::vector<char> pathBuffer(pathLen);
//         if (read(new_socket, pathBuffer.data(), pathLen) <= 0) {
//             std::cerr << "❌ Failed to read file path, skipping...\n";
//             continue;
//         }

//         std::string filepath(pathBuffer.begin(), pathBuffer.end());
//         std::string normalizedPath = std::filesystem::path(filepath).lexically_normal().string();

//         int fileSize = 0;
//         if (read(new_socket, &fileSize, sizeof(fileSize)) <= 0 || fileSize <= 0) {
//             std::cerr << "❌ Invalid file size for: " << filepath << ", skipping...\n";
//             continue;
//         }

//         std::vector<char> fileContent(fileSize);
//         int bytesReadTotal = 0;
//         while (bytesReadTotal < fileSize) {
//             int bytes = read(new_socket, fileContent.data() + bytesReadTotal, fileSize - bytesReadTotal);
//             if (bytes <= 0) break;
//             bytesReadTotal += bytes;
//         }

//         std::string outputPath = "server_data/" + normalizedPath;
//         std::filesystem::create_directories(std::filesystem::path(outputPath).parent_path());

//         std::ofstream outFile(outputPath, std::ios::binary);
//         if (!outFile) {
//             std::cerr << "❌ Failed to create file: " << outputPath << "\n";
//             continue;
//         }
//         outFile.write(fileContent.data(), fileSize);
//         outFile.close();

//         std::cout << "✅ Saved file: " << outputPath << " (" << fileSize << " bytes)\n";

//         // 🧪 Verify integrity
//         std::string actualHash = picosha2::hash256_hex_string(fileContent.begin(), fileContent.end());
//         std::cout << "\n🔎 Starting Integrity Check for: " << filepath << "\n";
//         std::cout << "[Integrity Check] Expected: " << clientHashes[normalizedPath] << "\n";
//         std::cout << "[Integrity Check] Actual:   " << actualHash << "\n";
//         if (clientHashes[normalizedPath] == actualHash)
//             std::cout << "✅ Integrity verified for " << filepath << "\n";
//         else
//             std::cout << "❌ Integrity mismatch for " << filepath << "\n";
//     }

//     std::cout << "\n📁 Final keys in clientHashes:\n";
//     for (const auto& [k, _] : clientHashes) {
//         std::cout << "🧾 " << k << "\n";
//     }

//     close(new_socket);
//     close(server_fd);
//     return 0;
// }
// Modularized server.cpp with full function definitions
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sstream>
#include <unordered_map>
#include <fstream>
#include <vector>
#include <filesystem>
#include "../include/sha256.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 4096

SSL_CTX* initServerSSLContext() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "❌ Unable to create SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "certs/cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "certs/key.pem", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "❌ Failed to load cert or key\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int setupServerSocket() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        std::cerr << "❌ Socket failed\n";
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "❌ Bind failed\n";
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        std::cerr << "❌ Listen failed\n";
        exit(EXIT_FAILURE);
    }

    std::cout << "🟢 Server listening on port " << PORT << "...\n";
    return server_fd;
}

int acceptClient(int server_fd) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    int new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    if (new_socket < 0) {
        std::cerr << "❌ Accept failed\n";
        exit(EXIT_FAILURE);
    }
    std::cout << "🔗 Client connected!\n";
    return new_socket;
}

std::unordered_map<std::string, std::string> parseSerializedData(const std::string& data) {
    std::unordered_map<std::string, std::string> result;
    std::istringstream stream(data);
    std::string line;
    while (std::getline(stream, line)) {
        size_t delimiterPos = line.find('|');
        if (delimiterPos != std::string::npos) {
            std::string path = line.substr(0, delimiterPos);
            std::string hash = line.substr(delimiterPos + 1);
            std::string normalized = std::filesystem::path(path).lexically_normal().string();
            result[normalized] = hash;
        }
    }
    return result;
}

std::unordered_map<std::string, std::string> receiveHashesFromClient(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    int dataSize = 0;
    SSL_read(ssl, &dataSize, sizeof(dataSize));

    std::string receivedData;
    int totalRead = 0;
    while (totalRead < dataSize) {
        int bytesRead = SSL_read(ssl, buffer, std::min(BUFFER_SIZE, dataSize - totalRead));
        if (bytesRead <= 0) break;
        receivedData.append(buffer, bytesRead);
        totalRead += bytesRead;
    }
    return parseSerializedData(receivedData);
}

std::vector<std::string> receiveDeletedFiles(SSL* ssl) {
    int numDeleted = 0;
    SSL_read(ssl, &numDeleted, sizeof(numDeleted));
    std::vector<std::string> deletedFiles;
    for (int i = 0; i < numDeleted; ++i) {
        int pathLen = 0;
        SSL_read(ssl, &pathLen, sizeof(pathLen));
        std::vector<char> delBuf(pathLen);
        SSL_read(ssl, delBuf.data(), pathLen);
        deletedFiles.push_back(std::filesystem::path(std::string(delBuf.begin(), delBuf.end())).lexically_normal().string());
    }
    return deletedFiles;
}

void deleteFilesFromServer(const std::vector<std::string>& deletedFiles) {
    for (const std::string& deletedPath : deletedFiles) {
        std::string fullPath = "server_data/" + deletedPath;
        std::filesystem::path normalized = std::filesystem::path(fullPath).lexically_normal();
        try {
            if (std::filesystem::exists(normalized)) {
                bool removed = std::filesystem::remove(normalized);
                std::cout << (removed ? "✅ Deleted: " : "⚠️ Not removed: ") << normalized << "\n";
            } else {
                std::cout << "⚠️ File not found: " << normalized << "\n";
            }
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "❌ Error deleting " << normalized << ": " << e.what() << "\n";
        }
    }
}

std::unordered_map<std::string, std::string> loadPreviousHashes(const std::string& filename) {
    std::unordered_map<std::string, std::string> oldHashes;
    std::ifstream infile(filename);
    std::string line;
    while (std::getline(infile, line)) {
        size_t delimiterPos = line.find('|');
        if (delimiterPos != std::string::npos) {
            std::string path = std::filesystem::path(line.substr(0, delimiterPos)).lexically_normal().string();
            std::string hash = line.substr(delimiterPos + 1);
            oldHashes[path] = hash;
        }
    }
    return oldHashes;
}

void compareHashes(const std::unordered_map<std::string, std::string>& oldHashes,
                   const std::unordered_map<std::string, std::string>& newHashes) {
    std::cout << "\n🔍 Change Detection:\n";
    for (const auto& [path, hash] : newHashes) {
        if (oldHashes.count(path)) {
            std::cout << (oldHashes.at(path) == hash ? "✅ Unchanged: " : "✏️ Modified: ") << path << "\n";
        } else {
            std::cout << "🆕 New File: " << path << "\n";
        }
    }
    for (const auto& [path, _] : oldHashes) {
        if (!newHashes.count(path)) {
            std::cout << "❌ Deleted File: " << path << "\n";
        }
    }
}

void saveHashes(const std::unordered_map<std::string, std::string>& hashes, const std::string& filename) {
    std::ofstream outfile(filename);
    for (const auto& [path, hash] : hashes) {
        outfile << path << "|" << hash << "\n";
    }
}

void requestFiles(SSL* ssl, const std::unordered_map<std::string, std::string>& newHashes,
                  const std::unordered_map<std::string, std::string>& oldHashes) {
    std::vector<std::string> filesToRequest;
    for (const auto& [path, hash] : newHashes) {
        if (!oldHashes.count(path) || oldHashes.at(path) != hash) {
            filesToRequest.push_back(path);
        }
    }
    std::ostringstream requestMessage;
    for (const auto& filePath : filesToRequest) {
        requestMessage << filePath << "\n";
    }
    std::string reqStr = requestMessage.str();
    int numFiles = filesToRequest.size();
    int msgLength = reqStr.size();
    SSL_write(ssl, &numFiles, sizeof(numFiles));
    SSL_write(ssl, &msgLength, sizeof(msgLength));
    SSL_write(ssl, reqStr.c_str(), msgLength);
    std::cout << "📤 Requested " << numFiles << " file(s) from client\n";
}

void receiveFiles(SSL* ssl, const std::unordered_map<std::string, std::string>& expectedHashes) {
    for (size_t i = 0; i < expectedHashes.size(); ++i) {
        int pathLen = 0;
        if (SSL_read(ssl, &pathLen, sizeof(pathLen)) <= 0 || pathLen <= 0) continue;

        std::vector<char> pathBuffer(pathLen);
        if (SSL_read(ssl, pathBuffer.data(), pathLen) <= 0) continue;

        std::string filepath(pathBuffer.begin(), pathBuffer.end());
        std::string normalizedPath = std::filesystem::path(filepath).lexically_normal().string();

        int fileSize = 0;
        if (SSL_read(ssl, &fileSize, sizeof(fileSize)) <= 0 || fileSize <= 0) continue;

        std::vector<char> fileContent(fileSize);
        int bytesReadTotal = 0;
        while (bytesReadTotal < fileSize) {
            int bytes = SSL_read(ssl, fileContent.data() + bytesReadTotal, fileSize - bytesReadTotal);
            if (bytes <= 0) break;
            bytesReadTotal += bytes;
        }

        std::string outputPath = "server_data/" + normalizedPath;
        std::filesystem::create_directories(std::filesystem::path(outputPath).parent_path());
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) continue;
        outFile.write(fileContent.data(), fileSize);
        outFile.close();

        std::string actualHash = picosha2::hash256_hex_string(fileContent.begin(), fileContent.end());
        std::cout << "\n🔎 Integrity Check for: " << filepath << "\n";
        std::cout << "Expected: " << expectedHashes.at(normalizedPath) << "\n";
        std::cout << "Actual:   " << actualHash << "\n";
        std::cout << (expectedHashes.at(normalizedPath) == actualHash ? "✅ Verified\n" : "❌ Mismatch\n");
    }
}

int main() {
    int server_fd = setupServerSocket();
    int rawSock = acceptClient(server_fd);
    SSL_CTX* ctx = initServerSSLContext();
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, rawSock);

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "❌ SSL accept failed\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    std::cout << "🔐 SSL handshake completed!\n";

    const std::string hashFile = "previous_hashes.txt";
    const char* greeting = "Hello from server!";
    SSL_write(ssl, greeting, strlen(greeting));

    auto clientHashes = receiveHashesFromClient(ssl);
    auto deleted = receiveDeletedFiles(ssl);
    deleteFilesFromServer(deleted);
    auto oldHashes = loadPreviousHashes(hashFile);
    compareHashes(oldHashes, clientHashes);
    saveHashes(clientHashes, hashFile);
    requestFiles(ssl, clientHashes, oldHashes);
    receiveFiles(ssl, clientHashes);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(rawSock);
    close(server_fd);
    return 0;
}