#include "hash_util.h"              // Our own header file
#include "../include/sha256.h"      // SHA256 implementation
#include <fstream>                  // For reading files
#include <sstream>                  // To read file into a string
#include <iostream>                 // For error messages

std::string getFileHash(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Could not open file: " << filePath << std::endl;
        return "";
    }

    std::ostringstream oss;
    oss << file.rdbuf();  // Read entire file into stream
    std::string fileData = oss.str();  // Convert stream to string

    return picosha2::hash256_hex_string(fileData);  // Generate hash
}
