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

#define PORT 8080
#define BUFFER_SIZE 4096

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
            std::cout << "🔍 Parsed: '" << path << "' -> '" << normalized << "' => " << hash << "\n";
            result[normalized] = hash;
        }
    }

    return result;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        std::cerr << "❌ Socket failed\n";
        return -1;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "❌ Bind failed\n";
        return -1;
    }

    if (listen(server_fd, 3) < 0) {
        std::cerr << "❌ Listen failed\n";
        return -1;
    }

    std::cout << "🟢 Server listening on port " << PORT << "...\n";

    new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        std::cerr << "❌ Accept failed\n";
        return -1;
    }

    std::cout << "🔗 Client connected!\n";

    const char* greeting = "Hello from server!";
    send(new_socket, greeting, strlen(greeting), 0);

    int dataSize = 0;
    read(new_socket, &dataSize, sizeof(dataSize));

    std::string receivedData;
    int totalRead = 0;
    while (totalRead < dataSize) {
        int bytesRead = read(new_socket, buffer, std::min(BUFFER_SIZE, dataSize - totalRead));
        if (bytesRead <= 0) break;
        receivedData.append(buffer, bytesRead);
        totalRead += bytesRead;
    }

    std::unordered_map<std::string, std::string> clientHashes = parseSerializedData(receivedData);

    std::unordered_map<std::string, std::string> oldHashes;
    std::ifstream infile("previous_hashes.txt");
    std::string line;
    while (std::getline(infile, line)) {
        size_t delimiterPos = line.find('|');
        if (delimiterPos != std::string::npos) {
            std::string path = std::filesystem::path(line.substr(0, delimiterPos)).lexically_normal().string();
            std::string hash = line.substr(delimiterPos + 1);
            oldHashes[path] = hash;
        }
    }
    infile.close();

    std::cout << "\n🔍 Change Detection:\n";
    for (const auto& [path, hash] : clientHashes) {
        if (oldHashes.count(path)) {
            if (oldHashes[path] == hash)
                std::cout << "✅ Unchanged: " << path << "\n";
            else
                std::cout << "✏️ Modified: " << path << "\n";
        } else {
            std::cout << "🆕 New File: " << path << "\n";
        }
    }
    for (const auto& [path, _] : oldHashes) {
        if (!clientHashes.count(path)) {
            std::cout << "❌ Deleted File: " << path << "\n";
        }
    }

    std::ofstream outfile("previous_hashes.txt");
    for (const auto& [path, hash] : clientHashes) {
        outfile << path << "|" << hash << "\n";
    }
    outfile.close();

    std::vector<std::string> filesToRequest;
    for (const auto& [path, hash] : clientHashes) {
        if (!oldHashes.count(path) || oldHashes[path] != hash) {
            filesToRequest.push_back(path);
        }
    }

    std::string requestMessage;
    for (const std::string& filePath : filesToRequest) {
        requestMessage += filePath + "\n";
    }

    int numFiles = filesToRequest.size();
    send(new_socket, &numFiles, sizeof(numFiles), 0);
    int msgLength = requestMessage.size();
    send(new_socket, &msgLength, sizeof(msgLength), 0);
    send(new_socket, requestMessage.c_str(), msgLength, 0);

    std::cout << "📤 Requested " << numFiles << " file(s) from client\n";

    for (int i = 0; i < numFiles; ++i) {
        int pathLen = 0;
        if (read(new_socket, &pathLen, sizeof(pathLen)) <= 0 || pathLen <= 0) {
            std::cerr << "❌ Invalid path length received, skipping...\n";
            continue;
        }

        std::vector<char> pathBuffer(pathLen);
        if (read(new_socket, pathBuffer.data(), pathLen) <= 0) {
            std::cerr << "❌ Failed to read file path, skipping...\n";
            continue;
        }

        std::string filepath(pathBuffer.begin(), pathBuffer.end());
        std::string normalizedPath = std::filesystem::path(filepath).lexically_normal().string();
        std::cout << "[Server Debug] Receiving file: " << normalizedPath << "\n";

        int fileSize = 0;
        if (read(new_socket, &fileSize, sizeof(fileSize)) <= 0 || fileSize <= 0) {
            std::cerr << "❌ Invalid file size for: " << filepath << ", skipping...\n";
            continue;
        }

        std::vector<char> fileContent(fileSize);
        int bytesReadTotal = 0;
        while (bytesReadTotal < fileSize) {
            int bytes = read(new_socket, fileContent.data() + bytesReadTotal, fileSize - bytesReadTotal);
            if (bytes <= 0) {
                std::cerr << "❌ Failed to read file content: " << filepath << "\n";
                break;
            }
            bytesReadTotal += bytes;
        }

        std::string outputPath = "server_data/" + normalizedPath;
        std::filesystem::create_directories(std::filesystem::path(outputPath).parent_path());

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) {
            std::cerr << "❌ Failed to create file: " << outputPath << "\n";
            continue;
        }
        outFile.write(fileContent.data(), fileSize);
        outFile.close();

        std::cout << "✅ Saved file: " << outputPath << " (" << fileSize << " bytes)\n";

        // 🔍 Integrity Check
        std::cout << "\n🔎 Starting Integrity Check for: " << normalizedPath << "\n";

        if (!clientHashes.count(normalizedPath)) {
            std::cerr << "⚠️ No hash found for: " << normalizedPath << " — checking fallback...\n";
            for (const auto& [k, _] : clientHashes) {
                if (std::filesystem::path(k).filename() == std::filesystem::path(normalizedPath).filename()) {
                    normalizedPath = k;
                    std::cout << "✅ Fallback match: " << k << "\n";
                    break;
                }
            }
        }

        if (!clientHashes.count(normalizedPath)) {
            std::cerr << "❌ No hash match for received file: " << normalizedPath << "\n";
            continue;
        }

        std::ifstream verifyFile(outputPath, std::ios::binary);
        if (verifyFile) {
            std::vector<unsigned char> verifyBuffer((std::istreambuf_iterator<char>(verifyFile)), {});
            std::string actualHash = picosha2::hash256_hex_string(verifyBuffer);
            std::string expectedHash = clientHashes[normalizedPath];

            std::cout << "[Integrity Check] Expected: " << expectedHash << "\n";
            std::cout << "[Integrity Check] Actual:   " << actualHash << "\n";

            if (actualHash == expectedHash) {
                std::cout << "✅ Integrity verified for " << normalizedPath << "\n";
            } else {
                std::cerr << "❌ Hash mismatch for " << normalizedPath << "\n";
            }
        } else {
            std::cerr << "❌ Could not reopen file for verification: " << outputPath << "\n";
        }
    }

    // Dump all keys for debugging
    std::cout << "\n📁 Final keys in clientHashes:\n";
    for (const auto& [k, _] : clientHashes) {
        std::cout << "🧾 " << k << "\n";
    }

    close(new_socket);
    close(server_fd);
    return 0;
}
