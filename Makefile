CXX = g++
CXXFLAGS = -std=c++17 -Wall -Iinclude
LDFLAGS = -lssl -lcrypto

SRC_DIR = src
UTIL_DIR = $(SRC_DIR)/utils
BIN_DIR = bin

CLIENT_SRC = $(SRC_DIR)/client.cpp $(UTIL_DIR)/hash_util.cpp
SERVER_SRC = $(SRC_DIR)/server.cpp $(UTIL_DIR)/hash_util.cpp

CLIENT_EXEC = $(BIN_DIR)/client_exec
SERVER_EXEC = $(BIN_DIR)/server_exec

all: $(CLIENT_EXEC) $(SERVER_EXEC)

$(CLIENT_EXEC): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(SERVER_EXEC): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(BIN_DIR)/*
