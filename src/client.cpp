#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <sstream>
#include "../include/sha256.h"  // Adjust path if needed

#define PORT 8080
#define BUFFER_SIZE 1024

// --- 🔐 Hash function with CRLF → LF normalization ---
std::string computeFileHash(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "❌ Could not open file: " << filepath << "\n";
        return "";
    }

    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
    std::vector<unsigned char> normalized;

    for (size_t i = 0; i < buffer.size(); ++i) {
        if (buffer[i] == '\r' && i + 1 < buffer.size() && buffer[i + 1] == '\n') {
            normalized.push_back('\n');
            ++i; // Skip '\n' from \r\n
        } else {
            normalized.push_back(buffer[i]);
        }
    }

    return picosha2::hash256_hex_string(normalized);
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "❌ Socket creation error\n";
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cerr << "❌ Invalid address / Address not supported\n";
        return -1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "❌ Connection Failed\n";
        return -1;
    }

    // Receive greeting
    read(sock, buffer, BUFFER_SIZE);
    std::cout << "📩 Received from server: " << buffer << std::endl;
    memset(buffer, 0, sizeof(buffer));

    // Hash files
    std::string directoryPath = "./test_files";
    std::unordered_map<std::string, std::string> fileHashes;

    std::cout << "\n🔍 Computing file hashes...\n";
    for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath)) {
        if (entry.is_regular_file()) {
            std::filesystem::path relPath = std::filesystem::relative(entry.path(), directoryPath);
            std::string normalizedPath = relPath.generic_string(); // Use forward slashes
            std::string fullPath = entry.path().string();
            std::string hash = computeFileHash(fullPath);
            fileHashes[normalizedPath] = hash;

            std::cout << "📄 File: " << normalizedPath << "\n🔐 Hash: " << hash << "\n\n";
        }
    }

    // Serialize hashes
    std::ostringstream ss;
    ss << "Hello from client!\n";
    for (const auto& [path, hash] : fileHashes) {
        ss << path << "|" << hash << "\n";
    }
    std::string allData = ss.str();

    std::cout << "📤 Sending to server:\n" << allData << "\n";

    // Send data length + actual data
    int dataSize = allData.size();
    send(sock, &dataSize, sizeof(dataSize), 0);
    send(sock, allData.c_str(), dataSize, 0);
    std::cout << "✅ Sent greeting + file hashes to server\n";

    // Receive requested file list
    int numFilesToSend = 0;
    read(sock, &numFilesToSend, sizeof(numFilesToSend));
    std::cout << "📥 Server requested " << numFilesToSend << " file(s)\n";

    int msgLength = 0;
    read(sock, &msgLength, sizeof(msgLength));

    int totalRead = 0;
    std::string filePathsRaw;
    while (totalRead < msgLength) {
        int bytes = read(sock, buffer, std::min(BUFFER_SIZE, msgLength - totalRead));
        if (bytes <= 0) break;
        filePathsRaw.append(buffer, bytes);
        totalRead += bytes;
    }

    std::vector<std::string> filesToSend;
    std::istringstream pathStream(filePathsRaw);
    std::string line;
    while (std::getline(pathStream, line)) {
        if (!line.empty()) {
            filesToSend.push_back(line);
        }
    }

    // Send requested files
    for (const auto& relPath : filesToSend) {
        std::string fullPath = directoryPath + "/" + relPath;
        std::ifstream file(fullPath, std::ios::binary);
        if (!file) {
            std::cerr << "❌ Could not open file: " << fullPath << "\n";
            continue;
        }

        std::vector<char> fileData((std::istreambuf_iterator<char>(file)), {});
        int pathLen = relPath.size();
        int fileSize = fileData.size();

        std::cout << "📤 Sending file: " << relPath << " (" << fileSize << " bytes)\n";
        send(sock, &pathLen, sizeof(pathLen), 0);
        send(sock, relPath.c_str(), pathLen, 0);
        send(sock, &fileSize, sizeof(fileSize), 0);
        send(sock, fileData.data(), fileSize, 0);
    }

    shutdown(sock, SHUT_WR);
    close(sock);
    return 0;
}
