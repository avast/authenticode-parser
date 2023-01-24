#include "../../src/helper.h"

#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <openssl/asn1.h>

TEST(HelperModule, byte_array_init_0)
{
    ByteArray array;
    uint8_t data[10] = {0x1, 0x2, 0x3};
    int res = byte_array_init(&array, data, 10);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(array.len, 10);
    ASSERT_TRUE(array.data);
    EXPECT_TRUE(std::memcmp(array.data, data, array.len) == 0);
    free(array.data);
}

TEST(HelperModule, byte_array_init_1)
{
    ByteArray array;
    uint8_t data[1] = {0x1};
    int res = byte_array_init(&array, data, 1);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(array.len, 1);
    ASSERT_TRUE(array.data);
    EXPECT_TRUE(std::memcmp(array.data, data, array.len) == 0);
    free(array.data);
}

TEST(HelperModule, byte_array_init_2)
{
    ByteArray array;
    uint8_t data[10000] = {0x1, 0x5, 0x10, 0x11};
    int res = byte_array_init(&array, data, 10000);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(array.len, 10000);
    ASSERT_TRUE(array.data);
    EXPECT_TRUE(std::memcmp(array.data, data, array.len) == 0);
    free(array.data);
}

TEST(HelperModule, asn1_time_get_int64_t_0)
{
    auto asn1time = ASN1_TIME_new();
    ASN1_TIME_set(asn1time, 1527779085);
    int64_t res = ASN1_TIME_to_int64_t(asn1time);
    EXPECT_EQ(res, 1527779085);
    ASN1_TIME_free(asn1time);
}

TEST(HelperModule, asn1_time_get_int64_t_1)
{
    auto asn1time = ASN1_TIME_new();
    int succ = ASN1_TIME_set_string(asn1time, "211014101955Z");
    EXPECT_TRUE(succ);
    int64_t res = ASN1_TIME_to_int64_t(asn1time);
    EXPECT_EQ(res, 1634206795);
    ASN1_TIME_free(asn1time);
}

TEST(HelperModule, asn1_time_get_int64_t_2)
{
    auto asn1time = ASN1_TIME_new();
    int succ = ASN1_TIME_set_string_X509(asn1time, "19700102212340Z");
    EXPECT_TRUE(succ);
    int64_t res = ASN1_TIME_to_int64_t(asn1time);
    EXPECT_EQ(res, 163420);
    ASN1_TIME_free(asn1time);
}

TEST(HelperModule, calculate_digest)
{
    uint8_t data[3] = {'a', 'b', 'c'};
    const int sha1_len = 20;
    uint8_t hash[sha1_len];
    int res = calculate_digest(EVP_sha1(), data, 3, hash);
    EXPECT_EQ(res, sha1_len);
    uint8_t correct_hash[sha1_len] = {0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
                                      0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D};
    EXPECT_TRUE(std::memcmp(hash, correct_hash, sha1_len) == 0);
}
