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
#include <thread>
#include <chrono>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../include/sha256.h"

#define PORT 8080
#define BUFFER_SIZE 4096

SSL_CTX* initServerSSLContext() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "certs/cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "certs/key.pem", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load cert or key\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int setupServerSocket() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        std::cerr << "Socket failed\n";
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed\n";
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed\n";
        exit(EXIT_FAILURE);
    }

    std::cout << " Server listening on port " << PORT << "...\n";
    return server_fd;
}

std::pair<int, std::string> acceptClient(int server_fd) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    int new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    if (new_socket < 0) {
        std::cerr << "Accept failed\n";
        exit(EXIT_FAILURE);
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
    return {new_socket, std::string(client_ip)};
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
            result[std::filesystem::path(path).lexically_normal().string()] = hash;
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
        std::vector<char> buffer(pathLen);
        SSL_read(ssl, buffer.data(), pathLen);
        deletedFiles.push_back(std::filesystem::path(std::string(buffer.begin(), buffer.end())).lexically_normal().string());
    }
    return deletedFiles;
}

void deleteFilesFromServer(const std::vector<std::string>& files, const std::string& clientID) {
    for (const auto& path : files) {
        std::string fullPath = "server_data/" + clientID + "/" + path;
        try {
            if (std::filesystem::exists(fullPath)) {
                std::filesystem::remove(fullPath);
                std::cout << " Deleted: " << fullPath << "\n";
            } else {
                std::cout << " Not Found: " << fullPath << "\n";
            }
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Delete error: " << e.what() << "\n";
        }
    }
}

void saveHashes(const std::unordered_map<std::string, std::string>& hashes, const std::string& path) {
    std::ofstream out(path);
    for (const auto& [p, h] : hashes)
        out << p << "|" << h << "\n";
}

std::unordered_map<std::string, std::string> loadHashes(const std::string& path) {
    std::unordered_map<std::string, std::string> hashes;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        size_t delim = line.find('|');
        if (delim != std::string::npos) {
            std::string path = line.substr(0, delim);
            std::string hash = line.substr(delim + 1);
            hashes[path] = hash;
        }
    }
    return hashes;
}

void requestFiles(SSL* ssl,
                  const std::unordered_map<std::string, std::string>& newHashes,
                  const std::unordered_map<std::string, std::string>& oldHashes) {
    std::vector<std::string> filesToRequest;
    for (const auto& [path, hash] : newHashes) {
        if (!oldHashes.count(path) || oldHashes.at(path) != hash) {
            filesToRequest.push_back(path);
        }
    }

    std::ostringstream oss;
    for (const std::string& f : filesToRequest) oss << f << "\n";

    std::string req = oss.str();
    int numFiles = filesToRequest.size();
    int reqLen = req.length();

    SSL_write(ssl, &numFiles, sizeof(numFiles));
    SSL_write(ssl, &reqLen, sizeof(reqLen));
    SSL_write(ssl, req.c_str(), reqLen);
    std::cout << " Requested " << numFiles << " file(s) from client\n";
}

void receiveFiles(SSL* ssl,
                  const std::unordered_map<std::string, std::string>& expectedHashes,
                  const std::string& clientID) {
    for (size_t i = 0; i < expectedHashes.size(); ++i) {
        int pathLen = 0;
        if (SSL_read(ssl, &pathLen, sizeof(pathLen)) <= 0) continue;

        std::vector<char> pathBuf(pathLen);
        if (SSL_read(ssl, pathBuf.data(), pathLen) <= 0) continue;
        std::string filepath(pathBuf.begin(), pathBuf.end());

        int fileSize = 0;
        if (SSL_read(ssl, &fileSize, sizeof(fileSize)) <= 0) continue;

        std::vector<char> fileBuf(fileSize);
        int total = 0;
        while (total < fileSize) {
            int readNow = SSL_read(ssl, fileBuf.data() + total, fileSize - total);
            if (readNow <= 0) break;
            total += readNow;
        }

        std::string outPath = "server_data/" + clientID + "/" + filepath;
        std::filesystem::create_directories(std::filesystem::path(outPath).parent_path());
        std::ofstream out(outPath, std::ios::binary);
        out.write(fileBuf.data(), fileSize);

        std::string actualHash = picosha2::hash256_hex_string(fileBuf.begin(), fileBuf.end());
        std::string expectedHash = expectedHashes.at(filepath);

        std::cout << "\n🔎 Integrity Check for: " << filepath << "\n";
        std::cout << "Expected: " << expectedHash << "\n";
        std::cout << "Actual:   " << actualHash << "\n";
        std::cout << (expectedHash == actualHash ? " Verified\n" : "Mismatch\n");
    }
}

void handleClient(int sock, std::string clientIP, SSL_CTX* ctx) {
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "SSL accept failed\n";
        ERR_print_errors_fp(stderr);
        close(sock);
        return;
    }

    std::cout << " SSL handshake completed for " << clientIP << "!\n";

    // Read client ID
    int idLen;
    SSL_read(ssl, &idLen, sizeof(idLen));
    std::vector<char> idBuf(idLen);
    SSL_read(ssl, idBuf.data(), idLen);
    std::string clientID(idBuf.begin(), idBuf.end());
    std::cout << "Client ID: " << clientID << "\n";

    std::filesystem::create_directories("server_data/" + clientID);
    std::filesystem::create_directories("server_hashes");
    std::string hashPath = "server_hashes/hashes_" + clientID + ".txt";

    auto oldHashes = loadHashes(hashPath);
    auto newHashes = receiveHashesFromClient(ssl);
    auto deleted = receiveDeletedFiles(ssl);

    deleteFilesFromServer(deleted, clientID);
    requestFiles(ssl, newHashes, oldHashes);
    receiveFiles(ssl, newHashes, clientID);
    saveHashes(newHashes, hashPath);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    std::cout << " Connection closed for " << clientIP << "\n";
}

int main() {
    SSL_CTX* ctx = initServerSSLContext();
    int server_fd = setupServerSocket();

    while (true) {
        auto [sock, ip] = acceptClient(server_fd);
        std::thread(handleClient, sock, ip, ctx).detach();
    }

    SSL_CTX_free(ctx);
    close(server_fd);
    return 0;
}
