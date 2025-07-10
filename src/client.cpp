#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <unordered_map>
#include <string>
#include <sstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../include/sha256.h"

#define PORT 8080
#define BUFFER_SIZE 4096

SSL_CTX* initClientSSLContext() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Failed to create SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int createSocket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Socket creation error\n";
        exit(EXIT_FAILURE);
    }
    return sock;
}

bool connectToServer(int sock, const std::string& ip, int port) {
    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address\n";
        return false;
    }
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed\n";
        return false;
    }
    return true;
}

std::unordered_map<std::string, std::string> loadPreviousHashes(const std::string& filename) {
    std::unordered_map<std::string, std::string> hashes;
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line)) {
        size_t delim = line.find('|');
        if (delim != std::string::npos) {
            std::string path = std::filesystem::path(line.substr(0, delim)).lexically_normal().generic_string();
            std::string hash = line.substr(delim + 1);
            hashes[path] = hash;
        }
    }
    return hashes;
}

std::string computeFileHash(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
    std::vector<unsigned char> normalized;
    for (size_t i = 0; i < buffer.size(); ++i) {
        if (buffer[i] == '\r' && i + 1 < buffer.size() && buffer[i + 1] == '\n') {
            normalized.push_back('\n');
            ++i;
        } else {
            normalized.push_back(buffer[i]);
        }
    }
    return picosha2::hash256_hex_string(normalized);
}

std::unordered_map<std::string, std::string> computeFileHashes(const std::string& directoryPath) {
    std::unordered_map<std::string, std::string> fileHashes;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath)) {
        if (entry.is_regular_file()) {
            std::filesystem::path relPath = std::filesystem::relative(entry.path(), directoryPath);
            std::string normalizedPath = relPath.lexically_normal().generic_string();
            std::string fullPath = entry.path().string();
            std::string hash = computeFileHash(fullPath);
            fileHashes[normalizedPath] = hash;
        }
    }
    return fileHashes;
}

std::vector<std::string> detectDeletedFiles(const std::unordered_map<std::string, std::string>& oldHashes,
                                            const std::unordered_map<std::string, std::string>& newHashes) {
    std::vector<std::string> deletedFiles;
    for (const auto& [path, _] : oldHashes) {
        if (newHashes.find(path) == newHashes.end()) {
            deletedFiles.push_back(path);
        }
    }
    return deletedFiles;
}

void sendHashesToServer(SSL* ssl, const std::unordered_map<std::string, std::string>& hashes) {
    std::ostringstream ss;
    for (const auto& [path, hash] : hashes) {
        ss << path << "|" << hash << "\n";
    }
    std::string allData = ss.str();
    int dataSize = allData.size();
    SSL_write(ssl, &dataSize, sizeof(dataSize));
    SSL_write(ssl, allData.c_str(), dataSize);
}

void sendDeletedFilesToServer(SSL* ssl, const std::vector<std::string>& deletedFiles) {
    int delCount = deletedFiles.size();
    SSL_write(ssl, &delCount, sizeof(delCount));
    for (const std::string& delPath : deletedFiles) {
        int len = delPath.size();
        SSL_write(ssl, &len, sizeof(len));
        SSL_write(ssl, delPath.c_str(), len);
    }
}

std::vector<std::string> receiveFilesToSend(SSL* ssl) {
    int numFilesToSend = 0, msgLength = 0;
    SSL_read(ssl, &numFilesToSend, sizeof(numFilesToSend));
    SSL_read(ssl, &msgLength, sizeof(msgLength));

    std::string filePathsRaw;
    char buffer[BUFFER_SIZE];
    int totalRead = 0;
    while (totalRead < msgLength) {
        int bytes = SSL_read(ssl, buffer, std::min(BUFFER_SIZE, msgLength - totalRead));
        if (bytes <= 0) break;
        filePathsRaw.append(buffer, bytes);
        totalRead += bytes;
    }

    std::vector<std::string> filesToSend;
    std::istringstream pathStream(filePathsRaw);
    std::string line;
    while (std::getline(pathStream, line)) {
        if (!line.empty()) filesToSend.push_back(line);
    }
    return filesToSend;
}

void sendRequestedFiles(SSL* ssl, const std::vector<std::string>& filesToSend, const std::string& directoryPath) {
    for (const auto& relPath : filesToSend) {
        std::string fullPath = directoryPath + "/" + relPath;
        std::ifstream file(fullPath, std::ios::binary);
        if (!file) continue;
        std::vector<char> fileData((std::istreambuf_iterator<char>(file)), {});
        int pathLen = relPath.size();
        int fileSize = fileData.size();
        SSL_write(ssl, &pathLen, sizeof(pathLen));
        SSL_write(ssl, relPath.c_str(), pathLen);
        SSL_write(ssl, &fileSize, sizeof(fileSize));
        SSL_write(ssl, fileData.data(), fileSize);
    }
}

void saveHashes(const std::unordered_map<std::string, std::string>& hashes, const std::string& filename) {
    std::ofstream updated(filename);
    for (const auto& [path, hash] : hashes) {
        updated << path << "|" << hash << "\n";
    }
}

int main(int argc, char* argv[]) {
    std::string clientID;
    if (argc >= 2) {
        clientID = argv[1];
    } else {
        char hostname[1024];
        gethostname(hostname, sizeof(hostname));
        clientID = std::string(hostname);
    }

    std::string directoryPath = "./test_files";
    std::string prevHashFile = "client_hashes/client_hashes_" + clientID + ".txt";

    int sock = createSocket();
    if (!connectToServer(sock, "127.0.0.1", PORT)) return -1;

    SSL_CTX* ctx = initClientSSLContext();
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL connection failed\n";
        ERR_print_errors_fp(stderr);
        return -1;
    }

    std::cout << "🔐 SSL handshake completed!\n";

    // Send client ID
    int idLen = clientID.size();
    SSL_write(ssl, &idLen, sizeof(idLen));
    SSL_write(ssl, clientID.c_str(), idLen);

    auto oldHashes = loadPreviousHashes(prevHashFile);
    auto newHashes = computeFileHashes(directoryPath);
    auto deletedFiles = detectDeletedFiles(oldHashes, newHashes);

    sendHashesToServer(ssl, newHashes);
    sendDeletedFilesToServer(ssl, deletedFiles);

    auto filesToSend = receiveFilesToSend(ssl);
    sendRequestedFiles(ssl, filesToSend, directoryPath);
    saveHashes(newHashes, prevHashFile);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
