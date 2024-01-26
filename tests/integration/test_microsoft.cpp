/* Copyright (c) 2021 Avast Software

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "../data.h"
#include <authenticode-parser/authenticode.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>

#include <gtest/gtest.h>

class MicrosoftSignatureTest : public testing::Test
{
  protected:
    unsigned char *data = nullptr;
    long data_len = 0;

    void SetUp() override
    {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO_write(
            bio,
            VALID_SIGNATURE_PEM_MICROSOFT_COUNTER,
            std::strlen(VALID_SIGNATURE_PEM_MICROSOFT_COUNTER));
        char *name = nullptr;
        char *header = nullptr;
        PEM_read_bio(bio, &name, &header, &data, &data_len);
        BIO_free_all(bio);
        OPENSSL_free(name);
        OPENSSL_free(header);

        initialize_authenticode_parser();
    }

    void TearDown() override { OPENSSL_free(data); }
};

TEST_F(MicrosoftSignatureTest, ResultOverview)
{
    AuthenticodeArray *auth = authenticode_new(data, data_len);
    ASSERT_NE(auth, nullptr);

    ASSERT_EQ(auth->count, 1);
    ASSERT_NE(auth->signatures, nullptr);

    for (size_t i = 0; i < auth->count; ++i) {
        ASSERT_TRUE(auth->signatures[i]);
    }

    authenticode_array_free(auth);
}

TEST_F(MicrosoftSignatureTest, SignatureContent)
{
    AuthenticodeArray *auth = authenticode_new(data, data_len);
    ASSERT_NE(auth, nullptr);

    ASSERT_EQ(auth->count, 1);
    ASSERT_NE(auth->signatures, nullptr);

    const Authenticode *first_sig = auth->signatures[0];
    ASSERT_TRUE(first_sig);

    //***********************************//
    // Check the first signature content //
    EXPECT_EQ(first_sig->version, 1);

    EXPECT_TRUE(first_sig->digest.data);
    uint8_t file_digest[32] = {0xc7, 0xfe, 0xf9, 0x4e, 0x32, 0x9b, 0xd9, 0xb6, 0x6b, 0x28, 0x15,
                               0x39, 0x26, 0x5f, 0x98, 0x93, 0x13, 0x35, 0x6c, 0xbd, 0x9c, 0x34,
                               0x5d, 0xf9, 0xe6, 0x70, 0xe9, 0xc4, 0xb6, 0xe0, 0xed, 0xce};
    EXPECT_EQ(first_sig->digest.len, 32);
    EXPECT_TRUE(std::memcmp(file_digest, first_sig->digest.data, 32) == 0);
    EXPECT_STREQ(first_sig->digest_alg, "sha256");

    EXPECT_EQ(first_sig->verify_flags, AUTHENTICODE_VFY_VALID);

    //****************************//
    // Check SignerInfo structure //
    ASSERT_TRUE(first_sig->signer);
    EXPECT_STREQ(first_sig->signer->digest_alg, "sha256");

    ASSERT_TRUE(first_sig->signer->digest.data);
    ASSERT_EQ(first_sig->signer->digest.len, 32);
    uint8_t message_digest[32] = {0x16, 0xef, 0xc5, 0x25, 0x0c, 0x4d, 0x4a, 0x99, 0xa0, 0x0e, 0xd2,
                                  0xad, 0x9a, 0x0e, 0x3d, 0x8f, 0xbc, 0x21, 0xda, 0x5b, 0xe9, 0x5a,
                                  0xc3, 0x5a, 0xd3, 0x3b, 0x3d, 0x9c, 0x3f, 0x37, 0x19, 0xa1};
    EXPECT_TRUE(std::memcmp(message_digest, first_sig->signer->digest.data, 32) == 0);
    ASSERT_TRUE(first_sig->signer->program_name);
    ASSERT_STREQ(first_sig->signer->program_name, "Procexp");

    //******************************************//
    // Test all certificates of first signature //
    ASSERT_TRUE(first_sig->certs);
    ASSERT_TRUE(first_sig->certs->certs);
    ASSERT_EQ(first_sig->certs->count, 2);

    //**************************//
    // Check the 1. certificate //
    const Certificate *cert = first_sig->certs->certs[0];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char first_cert_sha1[20] = {0x92, 0xd7, 0x19, 0x2a, 0x7c, 0x31, 0x80,
                                         0x91, 0x2f, 0xf8, 0x41, 0x4f, 0x79, 0x09,
                                         0x73, 0xa0, 0x5c, 0x28, 0xf8, 0xb0};
    EXPECT_TRUE(std::memcmp(first_cert_sha1, cert->sha1.data, 20) == 0);
    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Hardware "
        "Compatibility Publisher");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Third Party "
        "Component CA 2012");

    //**************************//
    // Check the 2. certificate //
    cert = first_sig->certs->certs[1];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char second_cert_sha1[20] = {0x77, 0xa1, 0x0e, 0xbf, 0x07, 0x54, 0x27,
                                          0x25, 0x21, 0x8c, 0xd8, 0x3a, 0x01, 0xb5,
                                          0x21, 0xc5, 0x7b, 0xc6, 0x7f, 0x73};
    EXPECT_TRUE(std::memcmp(second_cert_sha1, cert->sha1.data, 20) == 0);

    //**************************//
    // Check the Counter signature //
    const Countersignature *countersig = first_sig->countersigs->counters[0];

    EXPECT_EQ(countersig->verify_flags, COUNTERSIGNATURE_VFY_VALID);
    EXPECT_STREQ(countersig->digest_alg, "sha256");
    EXPECT_EQ(countersig->sign_time, 1629165693);
    unsigned char first_countersig_digest[32] = {0xed, 0xdf, 0x8a, 0x45, 0x34, 0x0e, 0x16, 0xb3,
                                                 0x55, 0x6a, 0x8e, 0x52, 0xb3, 0xfc, 0xd2, 0xe7,
                                                 0x3c, 0x5c, 0x47, 0xd3, 0x6a, 0xa6, 0x71, 0x4f,
                                                 0xfe, 0xef, 0x2c, 0x19, 0x60, 0x37, 0x67, 0x6f};
    ASSERT_TRUE(countersig->digest.data);
    ASSERT_EQ(countersig->digest.len, 32);
    EXPECT_TRUE(std::memcmp(first_countersig_digest, countersig->digest.data, 32) == 0);

    ASSERT_TRUE(countersig->chain);
    EXPECT_EQ(countersig->chain->count, 2);

    //**************************//
    // Check the 1. certificate //
    cert = countersig->chain->certs[0];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char first_countercert_sha1[20] = {0x9a, 0xb3, 0xfa, 0x0a, 0x1a, 0xdb, 0xcf,
                                                0x46, 0xb1, 0xee, 0xce, 0x7b, 0x9f, 0x93,
                                                0xe8, 0xa7, 0x75, 0x42, 0xf2, 0x0c};
    EXPECT_TRUE(std::memcmp(first_countercert_sha1, cert->sha1.data, 20) == 0);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char first_countercert_sha256[32] = {0x8a, 0xaa, 0x18, 0x95, 0xfb, 0x3c, 0x0d, 0x0e,
                                                  0xba, 0x54, 0xec, 0x34, 0x41, 0xec, 0xc8, 0xb9,
                                                  0xef, 0x18, 0xba, 0x18, 0x13, 0x58, 0xb0, 0x68,
                                                  0xe0, 0x66, 0xaa, 0xb6, 0xa9, 0x53, 0x0a, 0x32};
    EXPECT_TRUE(std::memcmp(first_countercert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/OU=Microsoft Operations Puerto "
        "Rico/OU=Thales TSS ESN:32BD-E3D5-3B1D/CN=Microsoft Time-Stamp Service");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Time-Stamp PCA 2010");
    EXPECT_EQ(cert->not_after, 1649703742);
    EXPECT_EQ(cert->not_before, 1610650942);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA74ah1Pa5wvcyvYNCy/"
        "YQs1tK8rIGlh1Qq1QFaJmYVXLXykb+m5yCStzmL227wJjsalZX8JA2YcbaZV5Icwm9vAJz8AC/sk/"
        "dsUK3pmDvkhtVI04YDV6otuZCILpQB9Ipcs3d0e1Dl2KKFvdibOk0/0rRxU9l+/"
        "Yxeb5lVTRERLxzI+Rd6Xv5QQYT6Sp2IE0N1vzIFd3yyO773T5XifNgL5lZbtIUnYUVmUBKlVoemO/"
        "54aiFeVBpIG+"
        "YzhDTF7cuHNAzxWIbP1wt4VIqAV9JjuqLMvvBSD56pi8NTKM9fxrERAeaTS2HbfBYfmnRZ27Czjeo0ijQ5DSZGi0Er"
        "vWfKQIDAQAB");
    EXPECT_STREQ(cert->serial, "33:00:00:01:62:d0:fe:02:f3:01:e5:cd:49:00:00:00:00:01:62");
    EXPECT_STREQ(cert->sig_alg, "sha256WithRSAEncryption");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //**************************//
    // Check the 2. certificate //
    cert = countersig->chain->certs[1];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char second_countercert_sha1[20] = {0x2a, 0xa7, 0x52, 0xfe, 0x64, 0xc4, 0x9a,
                                                 0xbe, 0x82, 0x91, 0x3c, 0x46, 0x35, 0x29,
                                                 0xcf, 0x10, 0xff, 0x2f, 0x04, 0xee};
    EXPECT_TRUE(std::memcmp(second_countercert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char second_countercert_sha256[32] = {0x86, 0xec, 0x11, 0x8d, 0x1e, 0xe6, 0x96, 0x70,
                                                   0xa4, 0x6e, 0x2b, 0xe2, 0x9c, 0x4b, 0x42, 0x08,
                                                   0xbe, 0x04, 0x3e, 0x36, 0x60, 0x0d, 0x4e, 0x1d,
                                                   0xd3, 0xf3, 0xd5, 0x15, 0xca, 0x11, 0x90, 0x20};
    EXPECT_TRUE(std::memcmp(second_countercert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject, "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Time-Stamp PCA 2010");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Root Certificate Authority 2010");
    EXPECT_EQ(cert->not_after, 1751406415);
    EXPECT_EQ(cert->not_before, 1278020215);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQAB");
    EXPECT_STREQ(cert->serial, "61:09:81:2a:00:00:00:00:00:02");
    EXPECT_STREQ(cert->sig_alg, "sha256WithRSAEncryption");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    authenticode_array_free(auth);
}
