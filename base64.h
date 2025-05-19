// base64.h
#pragma once

#include <string>

// Constants (externally visible if needed)
extern const std::string base64_chars;

// Helper function declarations
bool is_base64(unsigned char c);

// Main Base64 functions
std::string base64_encode(const unsigned char* bytes_to_encode, size_t in_len);
std::string base64_decode(const std::string& encoded_string);