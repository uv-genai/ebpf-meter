#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <arpa/inet.h> // For inet_pton
#include <iomanip>     // For std::hex

int main(int argc, char* argv[]) {
    // Check if filename is provided
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    std::string filename = argv[1];
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Error: Could not open file: " << filename << std::endl;
        return 1;
    }

    std::cout << "Processing file: " << filename << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    while (std::getline(file, line)) {
        if (line.empty()) continue;

        // 1. Replace all '*' with '255'
        // We loop because replacing * with 255 creates a new '2' which might be 
        // interpreted as a wildcard if we didn't loop, but here we just want to 
        // ensure all wildcards are replaced.
        while (line.find("*") != std::string::npos) {
            line.replace(line.find("*"), 1, "255");
        }

        // 2. Convert to Network Byte Order
        struct in_addr addr;
        if (inet_pton(AF_INET, line.c_str(), &addr) != 1) {
            std::cerr << "Error converting address: " << line << std::endl;
            continue;
        }

        // 3. Print the hex value to stdout
        uint32_t ip = addr.s_addr;
        std::cout << std::hex << ip << std::endl;
    }

    file.close();
    return 0;
}
