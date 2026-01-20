#include <iostream>
#include <string>
#include <cstring>
#include <arpa/inet.h> // Required for network functions
#include <iomanip>     // Required for std::hex, std::setw, std::setfill

// Function to print a 32-bit number in binary format
void printBinary(uint32_t num) {
    std::cout << "    Binary: ";
    for (int i = 31; i >= 0; --i) {
        std::cout << ((num >> i) & 1);
        if (i % 8 == 0) std::cout << " "; // Add a space every byte for readability
    }
    std::cout << std::endl;
}

int main() {
    std::string input_ip;
    struct in_addr ip_struct;
    char buffer[INET_ADDRSTRLEN];

    std::cout << "Enter an IP address (e.g., 192.168.1.1): ";
    std::cin >> input_ip;

    // 1. Convert string to Network Byte Order (binary)
    if (inet_pton(AF_INET, input_ip.c_str(), &ip_struct) != 1) {
        std::cerr << "Error converting address: " << strerror(errno) << std::endl;
        return 1;
    }

    uint32_t ip_as_int = ip_struct.s_addr;

    std::cout << "\n--- Analysis for IP: " << input_ip << " ---" << std::endl;

    // 2. Convert to Host Byte Order (Network Byte Order -> Host Byte Order)
    uint32_t host_order = ntohl(ip_as_int);

    // 3. Convert to Printable String
    if (inet_ntop(AF_INET, &ip_struct, buffer, INET_ADDRSTRLEN) != NULL) {
        std::cout << "1. Printable String: " << buffer << std::endl;
    }

    // 4. Print in Hexadecimal Format
    // std::hex sets base to 16, std::setw(8) pads with zeros, std::setfill pads with '0'
    std::cout << "\n2. Hexadecimal Format:" << std::endl;
    std::cout << "   Network Byte Order: 0x" << std::hex << std::setfill('0') << std::setw(8) << ip_as_int << std::endl;
    std::cout << "   Host Byte Order:   0x" << std::hex << std::setfill('0') << std::setw(8) << host_order << std::endl;

    // 5. Print in Binary Format
    std::cout << "\n3. Binary Format:" << std::endl;
    std::cout << "   Network Byte Order: ";
    printBinary(ip_as_int);
    
    std::cout << "   Host Byte Order:   ";
    printBinary(host_order);

    return 0;
}
