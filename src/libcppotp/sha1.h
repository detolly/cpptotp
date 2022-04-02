/**
 * @file sha1.h
 *
 * @brief The SHA-1 hash function.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#ifndef __CPPTOTP_SHA1_H__
#define __CPPTOTP_SHA1_H__

#include "bytes.h"

namespace CppTotp
{

typedef std::basic_string<unsigned char> (*HmacFunc)(const std::basic_string_view<unsigned char>, const std::basic_string_view<unsigned char>);

/**
 * Calculate the SHA-1 hash of the given message.
 */
std::basic_string<unsigned char> sha1(const std::basic_string_view<unsigned char> msg);

/**
 * Calculate the HMAC-SHA-1 hash of the given key/message pair.
 *
 * @note Most services assume a block size of 64.
 */
std::basic_string<unsigned char> hmacSha1(const std::basic_string_view<unsigned char> key, const std::basic_string_view<unsigned char> msg, std::size_t blockSize = 64);

}

#endif
