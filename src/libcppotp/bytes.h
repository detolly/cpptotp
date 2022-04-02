/**
 * @file bytes.h
 *
 * @brief Byte-related operations.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#ifndef __CPPTOTP_BYTES_H__
#define __CPPTOTP_BYTES_H__

#include <string>

#include <cstdint>

namespace CppTotp
{
namespace Bytes
{

/** Replaces target with source, clearing as much as possible. */
void swizzleByteStrings(std::basic_string<unsigned char>& target, std::basic_string<unsigned char>& source);

/** Converts a byte string into a hex string. */
std::string toHexString(const std::basic_string_view<unsigned char> bstr);

/** Converts an unsigned 32-bit integer into a corresponding byte string. */
std::basic_string<unsigned char> u32beToByteString(uint32_t num);

/** Converts an unsigned 64-bit integer into a corresponding byte string. */
std::basic_string<unsigned char> u64beToByteString(uint64_t num);

/** Converts a Base32 string into the correspoding byte string. */
std::basic_string<unsigned char> fromBase32(const std::string_view b32str);

/**
 * Converts a potentially unpadded Base32 string into the corresponding byte
 * string.
 */
std::basic_string<unsigned char> fromUnpaddedBase32(const std::string_view b32str);

/** Converts byte string into the corresponding Base32 string. */
std::string toBase32(const std::basic_string_view<unsigned char> b32str);


}
}

#endif
