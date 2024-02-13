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

class SignatureTest : public testing::Test
{
  protected:
    unsigned char *data = nullptr;
    long data_len = 0;

    void SetUp() override
    {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO_write(bio, VALID_SIGNATURE_PEM, std::strlen(VALID_SIGNATURE_PEM));
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

TEST_F(SignatureTest, ResultOverview)
{
    AuthenticodeArray *auth = authenticode_new(data, data_len);
    ASSERT_NE(auth, nullptr);

    ASSERT_EQ(auth->count, 3);
    ASSERT_NE(auth->signatures, nullptr);

    for (size_t i = 0; i < auth->count; ++i) {
        ASSERT_TRUE(auth->signatures[i]);
    }

    authenticode_array_free(auth);
}

TEST_F(SignatureTest, FirstSignatureContent)
{
    AuthenticodeArray *auth = authenticode_new(data, data_len);
    ASSERT_NE(auth, nullptr);

    ASSERT_EQ(auth->count, 3);
    ASSERT_NE(auth->signatures, nullptr);

    const Authenticode *first_sig = auth->signatures[0];
    ASSERT_TRUE(first_sig);

    //***********************************//
    // Check the first signature content //
    EXPECT_EQ(first_sig->version, 1);

    EXPECT_TRUE(first_sig->digest.data);
    unsigned char file_digest[20] = {0xfb, 0xf0, 0x17, 0xe2, 0x1d, 0x7b, 0xe9, 0x8d, 0xee, 0x4a,
                                     0x29, 0xe8, 0xf2, 0x9f, 0x05, 0xe5, 0xa4, 0x3b, 0x16, 0x9f};
    EXPECT_EQ(first_sig->digest.len, 20);
    EXPECT_TRUE(std::memcmp(file_digest, first_sig->digest.data, 20) == 0);
    EXPECT_STREQ(first_sig->digest_alg, "sha1");

    EXPECT_EQ(first_sig->verify_flags, AUTHENTICODE_VFY_VALID);

    //****************************//
    // Check SignerInfo structure //
    ASSERT_TRUE(first_sig->signer);
    EXPECT_STREQ(first_sig->signer->digest_alg, "sha1");

    ASSERT_TRUE(first_sig->signer->digest.data);
    ASSERT_EQ(first_sig->signer->digest.len, 20);
    unsigned char message_digest[20] = {0x26, 0x74, 0x14, 0x28, 0x0c, 0xa4, 0x8e, 0xa7, 0xa6, 0xff,
                                        0x1c, 0x67, 0xf3, 0x71, 0x32, 0x6d, 0x58, 0xe1, 0xe9, 0x60};

    EXPECT_TRUE(std::memcmp(message_digest, first_sig->signer->digest.data, 20) == 0);
    ASSERT_FALSE(first_sig->signer->program_name);

    //******************************************//
    // Test all certificates of first signature //
    ASSERT_TRUE(first_sig->certs);
    ASSERT_TRUE(first_sig->certs->certs);
    ASSERT_EQ(first_sig->certs->count, 4);

    //**************************//
    // Check the 1. certificate //
    const Certificate *cert = first_sig->certs->certs[0];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char first_cert_sha1[20] = {0x6c, 0x07, 0x45, 0x3f, 0xfd, 0xda, 0x08,
                                         0xb8, 0x37, 0x07, 0xc0, 0x9b, 0x82, 0xfb,
                                         0x3d, 0x15, 0xf3, 0x53, 0x36, 0xb1};
    EXPECT_TRUE(std::memcmp(first_cert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char first_cert_sha256[32] = {0x06, 0x25, 0xfe, 0xe1, 0xa8, 0x0d, 0x7b, 0x89,
                                           0x7a, 0x97, 0x12, 0x24, 0x9c, 0x2f, 0x55, 0xff,
                                           0x39, 0x1d, 0x66, 0x61, 0xdb, 0xd8, 0xb8, 0x7f,
                                           0x9b, 0xe6, 0xf2, 0x52, 0xd8, 0x8c, 0xed, 0x95};
    EXPECT_TRUE(std::memcmp(first_cert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject, "/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2");
    EXPECT_STREQ(
        cert->issuer,
        "/C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte "
        "Timestamping CA");
    EXPECT_EQ(cert->not_after, 1609372799);
    EXPECT_EQ(cert->not_before, 1356048000);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsayzSVRLlxwSCtgleZEiVypv3LgmxENza8K/"
        "LlBa+xTCdo5DASVDtKHiRfTot3vDdMwi17SUAAL3Te2/"
        "tLdEJGvNX0U70UTOQxJzF4KLabQry5kerHIbJk1xH7Ex3ftRYQJTpqr1SSwFeEWlL4nO55nn/"
        "oziVz89xpLcSvh7M+R5CvvwdYhBnP/"
        "FA1GZqtdsn5Nph2Upg4XCYBTEyMk7FNrAgfAfDXTekiKryvf7dHwn5vdKG3+"
        "nw54trorqpuaqJxZ9YfeYcRG84lChS+Vd+uUOpyyfqmUg09iW6Mh8pU5IRP8Z4kQHkgvXaISAXWp4ZEXNYEZ+"
        "VMETfMV58cnBcQIDAQAB");
    EXPECT_STREQ(cert->serial, "7e:93:eb:fb:7c:c6:4e:59:ea:4b:9a:77:d4:06:fc:3b");
    EXPECT_STREQ(cert->sig_alg, "sha1WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.5");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //**************************//
    // Check the 2. certificate //
    cert = first_sig->certs->certs[1];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char second_cert_sha1[20] = {0x65, 0x43, 0x99, 0x29, 0xb6, 0x79, 0x73,
                                          0xeb, 0x19, 0x2d, 0x6f, 0xf2, 0x43, 0xe6,
                                          0x76, 0x7a, 0xdf, 0x08, 0x34, 0xe4};
    EXPECT_TRUE(std::memcmp(second_cert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char second_cert_sha256[32] = {0x03, 0x74, 0x88, 0x1c, 0x9b, 0x74, 0xd3, 0x1f,
                                            0x28, 0xdc, 0x58, 0x0b, 0x0f, 0x2b, 0x9d, 0x2b,
                                            0x14, 0xa9, 0x7c, 0xe3, 0x1c, 0xbe, 0xc2, 0xa0,
                                            0x5a, 0xeb, 0x37, 0x7d, 0xcd, 0xdc, 0xc2, 0xb0};
    EXPECT_TRUE(std::memcmp(second_cert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services Signer - G4");
    EXPECT_STREQ(
        cert->issuer, "/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2");
    EXPECT_EQ(cert->not_after, 1609286399);
    EXPECT_EQ(cert->not_before, 1350518400);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5OwmNutLA9KxW7/"
        "hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0jkBP7oU4uRHFI/"
        "JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfultthO0VRHc8SVguSR/"
        "yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqhd5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsy"
        "i1aLM73ZY8hJnTrFxeozC9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB");
    EXPECT_STREQ(cert->serial, "0e:cf:f4:38:c8:fe:bf:35:6e:04:d8:6a:98:1b:1a:50");
    EXPECT_STREQ(cert->sig_alg, "sha1WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.5");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //**************************//
    // Check the 3. certificate //
    cert = first_sig->certs->certs[2];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char third_cert_sha1[20] = {0x33, 0xe2, 0x4f, 0xe6, 0x6e, 0x01, 0x17,
                                         0xfd, 0xd4, 0x27, 0x86, 0x99, 0xad, 0x42,
                                         0x3e, 0xf2, 0x66, 0x9f, 0xd2, 0x58};
    EXPECT_TRUE(std::memcmp(third_cert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char third_cert_sha256[32] = {0x51, 0xb4, 0xb0, 0xdf, 0x44, 0xa7, 0x40, 0xbc,
                                           0x08, 0x88, 0x17, 0x8c, 0xbe, 0xac, 0xe8, 0x31,
                                           0x08, 0xa2, 0x49, 0x9e, 0xc2, 0x2f, 0x39, 0x53,
                                           0x89, 0xa9, 0xd7, 0xc6, 0xab, 0x31, 0xbc, 0x42};
    EXPECT_TRUE(std::memcmp(third_cert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/ST=New York/L=New York/O=Slimware Utilities Holdings, Inc./CN=Slimware Utilities "
        "Holdings, Inc.");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=Terms of use at "
        "https://www.verisign.com/rpa (c)10/CN=VeriSign Class 3 Code Signing 2010 CA");
    EXPECT_EQ(cert->not_after, 1546905599);
    EXPECT_EQ(cert->not_before, 1513123200);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArkSLGMoBwKcg6EAppcjBQKHB2cOrlhmGjxdVSCVE+"
        "zOHHWVEx+5YP9KYiqShQ2ZPLw2SI9duq2ikRsShHboPgi6SfDb4OU44lsBP/H/"
        "sV9OrH2gaDi9IwN+XGzjKbOeIZ828m2GEf/t+kvoRmlxT0ivfiwzolsGqWsp3ELPrI/"
        "f+sVMFWrvPZPBGteH67qS+lwq5+4SX7DYJf2NPcJh9o+kYtU6FsY6MWe5oJSr3rhcTqknPhm8BYIKR/"
        "fRyjR+"
        "P2VYlUoytqjbM7QSACfMsa1Z6OZTMFEJV2iw7V14cyLNptCAU0w1mNtFD7RFYQKzjwkwPUm8dvBvaWSsSgqokZQIDA"
        "QAB");
    EXPECT_STREQ(cert->serial, "30:63:b3:a7:40:c1:cd:fd:f8:bb:9e:6c:33:1a:d7:de");
    EXPECT_STREQ(cert->sig_alg, "sha1WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.5");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //**************************//
    // Check the 4. certificate //
    cert = first_sig->certs->certs[3];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char fourth_cert_sha1[20] = {0x49, 0x58, 0x47, 0xa9, 0x31, 0x87, 0xcf,
                                          0xb8, 0xc7, 0x1f, 0x84, 0x0c, 0xb7, 0xb4,
                                          0x14, 0x97, 0xad, 0x95, 0xc6, 0x4f};
    EXPECT_TRUE(std::memcmp(fourth_cert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char fourth_cert_sha256[32] = {0x0c, 0xfc, 0x19, 0xdb, 0x68, 0x1b, 0x01, 0x4b,
                                            0xfe, 0x3f, 0x23, 0xcb, 0x3a, 0x78, 0xb6, 0x72,
                                            0x08, 0xb4, 0xe3, 0xd8, 0xd7, 0xb6, 0xa7, 0xb1,
                                            0x80, 0x7f, 0x7c, 0xd6, 0xec, 0xb2, 0xa5, 0x4e};
    EXPECT_TRUE(std::memcmp(fourth_cert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=Terms of use at "
        "https://www.verisign.com/rpa (c)10/CN=VeriSign Class 3 Code Signing 2010 CA");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For "
        "authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5");
    EXPECT_EQ(cert->not_after, 1581119999);
    EXPECT_EQ(cert->not_before, 1265587200);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9SNLXqXXirsy6dRX9+/kxyZ+rRmY/"
        "qidfZT2NmsQ13WBMH8EaH/LK3UezR0IjN9plKc3o5x7gOCZ4e43TV/"
        "OOxTuhtTQ9Sc1vCULOKeMY50Xowilq7D7zWpigkzVIdob2fHjhDuKKk+FW5ABT8mndhB/"
        "JwN8vq5+fcHd+QW8G0icaefApDw8QQA+35blxeSUcdZVAccAJkpAPLWhJqkMp22AjpAle8+/"
        "PxzrL5b65Yd3xrVWsno7VDBTG99iNP8e0fRakyiF5UwXTn5b/aSTmX/fze+kde/vFfZH5/"
        "gZctguNBqmtKdMfr27Tww9V/Ew1qY2jtaAdtcZLqXNfjQtiQIDAQAB");

    EXPECT_STREQ(cert->serial, "52:00:e5:aa:25:56:fc:1a:86:ed:96:c9:d4:4b:33:c7");
    EXPECT_STREQ(cert->sig_alg, "sha1WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.5");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //*******************************************//
    // Test the first signature countersignature //
    ASSERT_TRUE(first_sig->countersigs);
    ASSERT_TRUE(first_sig->countersigs->counters);
    ASSERT_EQ(first_sig->countersigs->count, 1);

    const Countersignature *countersig = first_sig->countersigs->counters[0];

    EXPECT_EQ(countersig->verify_flags, COUNTERSIGNATURE_VFY_VALID);
    EXPECT_STREQ(countersig->digest_alg, "sha1");
    EXPECT_EQ(countersig->sign_time, 1527779084);
    unsigned char first_countersig_digest[20] = {0xe0, 0x11, 0x73, 0x6f, 0xf0, 0x95, 0x6e,
                                                 0x4f, 0x97, 0xd3, 0x81, 0xc0, 0xd9, 0x8d,
                                                 0x46, 0x1d, 0xc2, 0x94, 0x69, 0x1b};
    ASSERT_TRUE(countersig->digest.data);
    ASSERT_EQ(countersig->digest.len, 20);
    EXPECT_TRUE(std::memcmp(first_countersig_digest, countersig->digest.data, 20) == 0);

    ASSERT_TRUE(countersig->chain);
    EXPECT_EQ(countersig->chain->count, 2);

    //**************************//
    // Check the 1. certificate //
    cert = countersig->chain->certs[0];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char first_countercert_sha1[20] = {0x65, 0x43, 0x99, 0x29, 0xb6, 0x79, 0x73,
                                                0xeb, 0x19, 0x2d, 0x6f, 0xf2, 0x43, 0xe6,
                                                0x76, 0x7a, 0xdf, 0x08, 0x34, 0xe4};
    EXPECT_TRUE(std::memcmp(first_countercert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char first_countercert_sha256[32] = {0x03, 0x74, 0x88, 0x1c, 0x9b, 0x74, 0xd3, 0x1f,
                                                  0x28, 0xdc, 0x58, 0x0b, 0x0f, 0x2b, 0x9d, 0x2b,
                                                  0x14, 0xa9, 0x7c, 0xe3, 0x1c, 0xbe, 0xc2, 0xa0,
                                                  0x5a, 0xeb, 0x37, 0x7d, 0xcd, 0xdc, 0xc2, 0xb0};
    EXPECT_TRUE(std::memcmp(first_countercert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services Signer - G4");
    EXPECT_STREQ(
        cert->issuer, "/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2");
    EXPECT_EQ(cert->not_after, 1609286399);
    EXPECT_EQ(cert->not_before, 1350518400);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5OwmNutLA9KxW7/"
        "hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0jkBP7oU4uRHFI/"
        "JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfultthO0VRHc8SVguSR/"
        "yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqhd5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsy"
        "i1aLM73ZY8hJnTrFxeozC9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB");
    EXPECT_STREQ(cert->serial, "0e:cf:f4:38:c8:fe:bf:35:6e:04:d8:6a:98:1b:1a:50");
    EXPECT_STREQ(cert->sig_alg, "sha1WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.5");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //**************************//
    // Check the 2. certificate //
    cert = countersig->chain->certs[1];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char second_countercert_sha1[20] = {0x6c, 0x07, 0x45, 0x3f, 0xfd, 0xda, 0x08,
                                                 0xb8, 0x37, 0x07, 0xc0, 0x9b, 0x82, 0xfb,
                                                 0x3d, 0x15, 0xf3, 0x53, 0x36, 0xb1};
    EXPECT_TRUE(std::memcmp(second_countercert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char second_countercert_sha256[32] = {0x06, 0x25, 0xfe, 0xe1, 0xa8, 0x0d, 0x7b, 0x89,
                                                   0x7a, 0x97, 0x12, 0x24, 0x9c, 0x2f, 0x55, 0xff,
                                                   0x39, 0x1d, 0x66, 0x61, 0xdb, 0xd8, 0xb8, 0x7f,
                                                   0x9b, 0xe6, 0xf2, 0x52, 0xd8, 0x8c, 0xed, 0x95};
    EXPECT_TRUE(std::memcmp(second_countercert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject, "/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2");
    EXPECT_STREQ(
        cert->issuer,
        "/C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte "
        "Timestamping CA");
    EXPECT_EQ(cert->not_after, 1609372799);
    EXPECT_EQ(cert->not_before, 1356048000);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsayzSVRLlxwSCtgleZEiVypv3LgmxENza8K/"
        "LlBa+xTCdo5DASVDtKHiRfTot3vDdMwi17SUAAL3Te2/"
        "tLdEJGvNX0U70UTOQxJzF4KLabQry5kerHIbJk1xH7Ex3ftRYQJTpqr1SSwFeEWlL4nO55nn/"
        "oziVz89xpLcSvh7M+R5CvvwdYhBnP/"
        "FA1GZqtdsn5Nph2Upg4XCYBTEyMk7FNrAgfAfDXTekiKryvf7dHwn5vdKG3+"
        "nw54trorqpuaqJxZ9YfeYcRG84lChS+Vd+uUOpyyfqmUg09iW6Mh8pU5IRP8Z4kQHkgvXaISAXWp4ZEXNYEZ+"
        "VMETfMV58cnBcQIDAQAB");
    EXPECT_STREQ(cert->serial, "7e:93:eb:fb:7c:c6:4e:59:ea:4b:9a:77:d4:06:fc:3b");
    EXPECT_STREQ(cert->sig_alg, "sha1WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.5");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    authenticode_array_free(auth);
}

TEST_F(SignatureTest, SecondSignatureContent)
{
    AuthenticodeArray *auth = authenticode_new(data, data_len);
    ASSERT_NE(auth, nullptr);

    ASSERT_EQ(auth->count, 3);
    ASSERT_NE(auth->signatures, nullptr);

    const Authenticode *second_sig = auth->signatures[1];
    ASSERT_TRUE(second_sig);

    //***********************************//
    // Check the second signature content //
    EXPECT_EQ(second_sig->version, 1);

    EXPECT_TRUE(second_sig->digest.data);
    unsigned char file_digest[20] = {0xfb, 0xf0, 0x17, 0xe2, 0x1d, 0x7b, 0xe9, 0x8d, 0xee, 0x4a,
                                     0x29, 0xe8, 0xf2, 0x9f, 0x05, 0xe5, 0xa4, 0x3b, 0x16, 0x9f};
    EXPECT_EQ(second_sig->digest.len, 20);
    EXPECT_TRUE(std::memcmp(file_digest, second_sig->digest.data, 20) == 0);
    EXPECT_STREQ(second_sig->digest_alg, "sha1");

    EXPECT_EQ(second_sig->verify_flags, AUTHENTICODE_VFY_VALID);

    //****************************//
    // Check SignerInfo structure //
    ASSERT_TRUE(second_sig->signer);
    EXPECT_STREQ(second_sig->signer->digest_alg, "sha1");

    ASSERT_TRUE(second_sig->signer->digest.data);
    ASSERT_EQ(second_sig->signer->digest.len, 20);
    unsigned char message_digest[20] = {0x26, 0x74, 0x14, 0x28, 0x0c, 0xa4, 0x8e, 0xa7, 0xa6, 0xff,
                                        0x1c, 0x67, 0xf3, 0x71, 0x32, 0x6d, 0x58, 0xe1, 0xe9, 0x60};

    EXPECT_TRUE(std::memcmp(message_digest, second_sig->signer->digest.data, 20) == 0);
    ASSERT_FALSE(second_sig->signer->program_name);

    EXPECT_TRUE(second_sig->signer->chain);
    EXPECT_EQ(second_sig->signer->chain->count, 1);

    //******************************************//
    // Test all certificates of first signature //
    ASSERT_TRUE(second_sig->certs);
    ASSERT_TRUE(second_sig->certs->certs);
    ASSERT_EQ(second_sig->certs->count, 3);

    //**************************//
    // Check the 1. certificate //
    const Certificate *cert = second_sig->certs->certs[0];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char first_cert_sha1[20] = {0xa1, 0x02, 0x1a, 0x18, 0x6a, 0x74, 0xc1,
                                         0x00, 0x51, 0x28, 0xf7, 0xb4, 0x59, 0xb4,
                                         0x9e, 0x2e, 0x2f, 0xec, 0xfb, 0x16};
    EXPECT_TRUE(std::memcmp(first_cert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char first_cert_sha256[32] = {0x7d, 0x77, 0x40, 0x36, 0x16, 0xf1, 0xac, 0x63,
                                           0xb3, 0xd1, 0x09, 0x9b, 0x93, 0xe1, 0x75, 0xb0,
                                           0x38, 0x82, 0xe0, 0xd9, 0xf7, 0x9c, 0xc5, 0x9c,
                                           0x1b, 0x7a, 0xfe, 0x22, 0x27, 0xc7, 0x69, 0x2d};
    EXPECT_TRUE(std::memcmp(first_cert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/ST=New York/L=New York City/O=Slimware Utilities Holdings, Inc./OU=White Label "
        "License/CN=Slimware Utilities Holdings, "
        "Inc./emailAddress=licensing@slimwareutilities.com");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/ST=MS/L=Ocean Springs/O=SlimWare Utilities Holdings, Inc./OU=White Label License "
        "Authority/CN=SlimWare Services License "
        "Authority/emailAddress=licensing@slimwareutilities.com");
    EXPECT_EQ(cert->not_after, 1533859199);
    EXPECT_EQ(cert->not_before, 1502323200);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyVjfnMBR+R+2lWS/"
        "tHl2ErRB8HqdwMnlePECoSfck4ZmLQp5+O6xOsJ/"
        "5R7gnle0mhdSkGslRdJwXo0ytH7f8r0+"
        "5m6YPbbGXIBj7CJI0C4aMW7kZ8Ykj6940FeqGfIWcRl50UysMsOrXXVy8cmbfsHL/"
        "kvOLb+IFgHvFQR2vaC86vRKUt7NAh7pEnxFyyAZZYVeDwSq0MSmCb4Cl9S6PifKK/"
        "Xtxu95Ae7AdiTrIFwgkafH6LHtoEdOq/"
        "2C5+c07XDlDeQ6yV9NdllYPvF87xeUazNO+lwL0ak4r6HByNogAGOedX7KADztmJTyXy2VFu+P/3zDqGxhm/"
        "HLEtEekQIDAQAB");
    EXPECT_STREQ(cert->serial, "06");
    EXPECT_STREQ(cert->sig_alg, "sha1WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.5");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //**************************//
    // Check the 2. certificate //
    cert = second_sig->certs->certs[1];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char second_cert_sha1[20] = {0x6f, 0xc9, 0xed, 0xb5, 0xe0, 0x0a, 0xb6,
                                          0x41, 0x51, 0xc1, 0xcd, 0xfc, 0xac, 0x74,
                                          0xad, 0x2c, 0x7b, 0x7e, 0x3b, 0xe4};
    EXPECT_TRUE(std::memcmp(second_cert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char second_cert_sha256[32] = {0xf3, 0x51, 0x6d, 0xdc, 0xc8, 0xaf, 0xc8, 0x08,
                                            0x78, 0x8b, 0xd8, 0xb0, 0xe8, 0x40, 0xbd, 0xa2,
                                            0xb5, 0xe2, 0x3c, 0x62, 0x44, 0x25, 0x2c, 0xa3,
                                            0x00, 0x0b, 0xb6, 0xc8, 0x71, 0x70, 0x40, 0x2a};
    EXPECT_TRUE(std::memcmp(second_cert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec SHA256 TimeStamping "
        "CA");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2008 VeriSign, Inc. - For "
        "authorized use only/CN=VeriSign Universal Root Certification Authority");
    EXPECT_EQ(cert->not_after, 1925942399);
    EXPECT_EQ(cert->not_before, 1452556800);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1mdWVVPnYxyXRqBoutV87ABrTxxrDKPBWuGmicAMpdqTc"
        "lkFEspu8LZKbku7GOz4c8/C1aQ+GIbfuumB+Lef15tQDjUkQbnQXx5HMvLrRu/2JWR8/"
        "DubPitljkuf8EnuHg5xYSl7e2vh47Ojcdt6tKYtTofHjmdw/SaqPSE4cTRfHHGBim0P+SDDSbDewg+TfkKtzNJ/"
        "8o71PWym0vhiJka9cDpMxTW38eA25Hu/"
        "rySV3J39M2ozP4J9ZM3vpWIasXc9LFL1M7oCZFftYR5NYp4rBkyjyPBMkEbWQ6pPrHM+"
        "dYr77fY5NUdbRE6kvaTyZzjSO67Uw7UNpeGeMWhNwIDAQAB");
    EXPECT_STREQ(cert->serial, "7b:05:b1:d4:49:68:51:44:f7:c9:89:d2:9c:19:9d:12");
    EXPECT_STREQ(cert->sig_alg, "sha256WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.11");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //**************************//
    // Check the 3. certificate //
    cert = second_sig->certs->certs[2];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char third_cert_sha1[20] = {0xa9, 0xa4, 0x12, 0x10, 0x63, 0xd7, 0x1d,
                                         0x48, 0xe8, 0x52, 0x9a, 0x46, 0x81, 0xde,
                                         0x80, 0x3e, 0x3e, 0x79, 0x54, 0xb0};
    EXPECT_TRUE(std::memcmp(third_cert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char third_cert_sha256[32] = {0xc4, 0x74, 0xce, 0x76, 0x00, 0x7d, 0x02, 0x39,
                                           0x4e, 0x0d, 0xa5, 0xe4, 0xde, 0x7c, 0x14, 0xc6,
                                           0x80, 0xf9, 0xe2, 0x82, 0x01, 0x3c, 0xfe, 0xf6,
                                           0x53, 0xef, 0x5d, 0xb7, 0x1f, 0xdf, 0x61, 0xf8};
    EXPECT_TRUE(std::memcmp(third_cert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec SHA256 TimeStamping "
        "Signer - G3");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec SHA256 TimeStamping "
        "CA");
    EXPECT_EQ(cert->not_after, 1868918399);
    EXPECT_EQ(cert->not_before, 1513987200);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArw6Kqvjcv2l7VBdxRwm9jTyB+"
        "HQVd2eQnP3eTgKeS3b25TY+ZdUkIG0w+d0dg+k/"
        "J0ozTm0WiuSNQI0iqr6nCxvSB7Y8tRokKPgbclE9yAmIJgg6+fpDI3VHcAyzX1uPCB1ySFdlTa8CPED39N0yOJM/"
        "5Sym81kjy4DeE035EMmqChhsVWFX0fECLMS1q/JsI9KfDQ8ZbK2FYmn9ToXBilIxq1vYyXRS41dsIr9Vf2/KBqs/"
        "SrcidmXs7DbylpWBJiz9u5iqATjTryVAmwlT8ClXhVhe6oVIQSGH5d600yaye0BTWHmOUjEGTZQDRcTOPAPstwDyOi"
        "LFtG/l77CKmwIDAQAB");
    EXPECT_STREQ(cert->serial, "7b:d4:e5:af:ba:cc:07:3f:a1:01:23:04:22:41:4d:12");
    EXPECT_STREQ(cert->sig_alg, "sha256WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.11");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //*******************************************//
    // Test the first signature countersignature //
    ASSERT_TRUE(second_sig->countersigs);
    ASSERT_TRUE(second_sig->countersigs->counters);
    ASSERT_EQ(second_sig->countersigs->count, 1);

    const Countersignature *countersig = second_sig->countersigs->counters[0];

    EXPECT_EQ(countersig->verify_flags, COUNTERSIGNATURE_VFY_VALID);
    EXPECT_STREQ(countersig->digest_alg, "sha1");
    EXPECT_EQ(countersig->sign_time, 1527779086);
    unsigned char first_countersig_digest[20] = {0x75, 0x86, 0x41, 0xf1, 0x7b, 0x4a, 0x7a,
                                                 0x86, 0x12, 0xd7, 0x02, 0xaf, 0x8b, 0x9f,
                                                 0xaf, 0x84, 0xb5, 0x06, 0xb5, 0xff};
    ASSERT_TRUE(countersig->digest.data);
    ASSERT_EQ(countersig->digest.len, 20);
    EXPECT_TRUE(std::memcmp(first_countersig_digest, countersig->digest.data, 20) == 0);

    ASSERT_TRUE(countersig->chain);
    EXPECT_EQ(countersig->chain->count, 2);

    //**************************//
    // Check the 1. certificate //
    cert = countersig->chain->certs[0];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char first_countercert_sha1[20] = {0xa9, 0xa4, 0x12, 0x10, 0x63, 0xd7, 0x1d,
                                                0x48, 0xe8, 0x52, 0x9a, 0x46, 0x81, 0xde,
                                                0x80, 0x3e, 0x3e, 0x79, 0x54, 0xb0};
    EXPECT_TRUE(std::memcmp(first_countercert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char first_countercert_sha256[32] = {0xc4, 0x74, 0xce, 0x76, 0x00, 0x7d, 0x02, 0x39,
                                                  0x4e, 0x0d, 0xa5, 0xe4, 0xde, 0x7c, 0x14, 0xc6,
                                                  0x80, 0xf9, 0xe2, 0x82, 0x01, 0x3c, 0xfe, 0xf6,
                                                  0x53, 0xef, 0x5d, 0xb7, 0x1f, 0xdf, 0x61, 0xf8};
    EXPECT_TRUE(std::memcmp(first_countercert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec SHA256 TimeStamping "
        "Signer - G3");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec SHA256 TimeStamping "
        "CA");
    EXPECT_EQ(cert->not_after, 1868918399);
    EXPECT_EQ(cert->not_before, 1513987200);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArw6Kqvjcv2l7VBdxRwm9jTyB+"
        "HQVd2eQnP3eTgKeS3b25TY+ZdUkIG0w+d0dg+k/"
        "J0ozTm0WiuSNQI0iqr6nCxvSB7Y8tRokKPgbclE9yAmIJgg6+fpDI3VHcAyzX1uPCB1ySFdlTa8CPED39N0yOJM/"
        "5Sym81kjy4DeE035EMmqChhsVWFX0fECLMS1q/JsI9KfDQ8ZbK2FYmn9ToXBilIxq1vYyXRS41dsIr9Vf2/KBqs/"
        "SrcidmXs7DbylpWBJiz9u5iqATjTryVAmwlT8ClXhVhe6oVIQSGH5d600yaye0BTWHmOUjEGTZQDRcTOPAPstwDyOi"
        "LFtG/l77CKmwIDAQAB");
    EXPECT_STREQ(cert->serial, "7b:d4:e5:af:ba:cc:07:3f:a1:01:23:04:22:41:4d:12");
    EXPECT_STREQ(cert->sig_alg, "sha256WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.11");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //**************************//
    // Check the 2. certificate //
    cert = countersig->chain->certs[1];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char second_countercert_sha1[20] = {0x6f, 0xc9, 0xed, 0xb5, 0xe0, 0x0a, 0xb6,
                                                 0x41, 0x51, 0xc1, 0xcd, 0xfc, 0xac, 0x74,
                                                 0xad, 0x2c, 0x7b, 0x7e, 0x3b, 0xe4};
    EXPECT_TRUE(std::memcmp(second_countercert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char second_countercert_sha256[32] = {0xf3, 0x51, 0x6d, 0xdc, 0xc8, 0xaf, 0xc8, 0x08,
                                                   0x78, 0x8b, 0xd8, 0xb0, 0xe8, 0x40, 0xbd, 0xa2,
                                                   0xb5, 0xe2, 0x3c, 0x62, 0x44, 0x25, 0x2c, 0xa3,
                                                   0x00, 0x0b, 0xb6, 0xc8, 0x71, 0x70, 0x40, 0x2a};
    EXPECT_TRUE(std::memcmp(second_countercert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec SHA256 TimeStamping "
        "CA");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2008 VeriSign, Inc. - For "
        "authorized use only/CN=VeriSign Universal Root Certification Authority");
    EXPECT_EQ(cert->not_after, 1925942399);
    EXPECT_EQ(cert->not_before, 1452556800);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1mdWVVPnYxyXRqBoutV87ABrTxxrDKPBWuGmicAMpdqTc"
        "lkFEspu8LZKbku7GOz4c8/C1aQ+GIbfuumB+Lef15tQDjUkQbnQXx5HMvLrRu/2JWR8/"
        "DubPitljkuf8EnuHg5xYSl7e2vh47Ojcdt6tKYtTofHjmdw/SaqPSE4cTRfHHGBim0P+SDDSbDewg+TfkKtzNJ/"
        "8o71PWym0vhiJka9cDpMxTW38eA25Hu/"
        "rySV3J39M2ozP4J9ZM3vpWIasXc9LFL1M7oCZFftYR5NYp4rBkyjyPBMkEbWQ6pPrHM+"
        "dYr77fY5NUdbRE6kvaTyZzjSO67Uw7UNpeGeMWhNwIDAQAB");
    EXPECT_STREQ(cert->serial, "7b:05:b1:d4:49:68:51:44:f7:c9:89:d2:9c:19:9d:12");
    EXPECT_STREQ(cert->sig_alg, "sha256WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.11");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    authenticode_array_free(auth);
}

TEST_F(SignatureTest, ThirdSignatureContent)
{
    AuthenticodeArray *auth = authenticode_new(data, data_len);
    ASSERT_NE(auth, nullptr);

    ASSERT_EQ(auth->count, 3);
    ASSERT_NE(auth->signatures, nullptr);

    const Authenticode *third_sig = auth->signatures[2];
    ASSERT_TRUE(third_sig);

    //***********************************//
    // Check the third signature content //
    EXPECT_EQ(third_sig->version, 1);

    EXPECT_TRUE(third_sig->digest.data);
    unsigned char file_digest[32] = {0x3c, 0x3a, 0x78, 0x3f, 0x91, 0x69, 0x22, 0xc6,
                                     0x57, 0x1d, 0x6d, 0x1d, 0xcb, 0xb4, 0x25, 0xe8,
                                     0xb3, 0x42, 0xd1, 0x54, 0x66, 0xa3, 0x30, 0xe2,
                                     0xd4, 0x82, 0x1c, 0x3a, 0xc9, 0xef, 0x32, 0xe8};
    EXPECT_EQ(third_sig->digest.len, 32);
    EXPECT_TRUE(std::memcmp(file_digest, third_sig->digest.data, 32) == 0);
    EXPECT_STREQ(third_sig->digest_alg, "sha256");

    EXPECT_EQ(third_sig->verify_flags, AUTHENTICODE_VFY_VALID);

    //****************************//
    // Check SignerInfo structure //
    ASSERT_TRUE(third_sig->signer);
    EXPECT_STREQ(third_sig->signer->digest_alg, "sha256");

    ASSERT_TRUE(third_sig->signer->digest.data);
    ASSERT_EQ(third_sig->signer->digest.len, 32);
    unsigned char message_digest[32] = {0xec, 0xbe, 0x17, 0x5e, 0xc3, 0x50, 0x8b, 0xdc,
                                        0xff, 0xb4, 0x31, 0x2e, 0x91, 0x0f, 0x13, 0xb4,
                                        0x3a, 0x65, 0xd3, 0xc1, 0x95, 0xcd, 0x15, 0x31,
                                        0xca, 0x34, 0xfd, 0x83, 0x72, 0x0b, 0x6a, 0x06};

    EXPECT_TRUE(std::memcmp(message_digest, third_sig->signer->digest.data, 32) == 0);
    ASSERT_FALSE(third_sig->signer->program_name);

    EXPECT_TRUE(third_sig->signer->chain);
    EXPECT_EQ(third_sig->signer->chain->count, 2);

    //************************************//
    // Test the signer ceritificate chain //

    //**************************//
    // Check the 1. certificate //
    const Certificate *cert = third_sig->signer->chain->certs[0];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char first_cert_sha1[20] = {0x38, 0xee, 0x42, 0xb7, 0x35, 0xf3, 0x64,
                                         0x16, 0xeb, 0xb2, 0xf1, 0xb5, 0xd7, 0x3c,
                                         0xdf, 0xf4, 0x04, 0x34, 0x19, 0xb2};
    EXPECT_TRUE(std::memcmp(first_cert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char first_cert_sha256[32] = {0x10, 0x38, 0xf9, 0x71, 0xdc, 0x51, 0xb4, 0xe7,
                                           0xbd, 0xd3, 0x8b, 0x8c, 0x38, 0x74, 0xf5, 0x10,
                                           0x90, 0x1c, 0x1b, 0xc4, 0x1c, 0x0d, 0xbb, 0xb2,
                                           0x50, 0x7b, 0x2b, 0x09, 0x27, 0xca, 0xd1, 0xae};
    EXPECT_TRUE(std::memcmp(first_cert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/ST=New York/L=New York/O=Slimware Utilities Holdings, Inc./CN=Slimware Utilities "
        "Holdings, Inc.");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 3 SHA256 Code "
        "Signing CA");
    EXPECT_EQ(cert->not_after, 1579046399);
    EXPECT_EQ(cert->not_before, 1513036800);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNL1QMjGVITZlLmtDZ71zX5tlNvwDdaPIE9TqY742KxKtm"
        "MhfGtkBfk52jopOWYVnZMKvOrmP8cAfh5nRpYRWXxt9qKk1oR46y/"
        "plOsC1rZItp1fRbCdZENLxp2K1tFXHmbL6EhDN0GZRZliqZzSRljEIHblWeFahl/YZKbwpaT/NfNMu3ShQ8nO/"
        "9SUssi0w0z8EyIm1SZBEgByJ2C8YV0Hw19jiKm09lLLY8zJLfSZxi9uM5wdJoJNVRALCr4+yyKvwE+"
        "uSqHn5HrLf0OSQbUwmw2e6FhCpdlDr/Ojx8fT/rX7Nqs7T+wGjP6zk8CU/NXzC4IlnTypJ/gVpkVP4QIDAQAB");
    EXPECT_STREQ(cert->serial, "38:bf:a6:1b:82:b8:0f:60:57:15:e4:8a:a1:0d:e1:53");
    EXPECT_STREQ(cert->sig_alg, "sha256WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.11");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    //**************************//
    // Check the 2. certificate //
    cert = third_sig->signer->chain->certs[1];
    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    unsigned char second_cert_sha1[20] = {0x00, 0x77, 0x90, 0xf6, 0x56, 0x1d, 0xad,
                                          0x89, 0xb0, 0xbc, 0xd8, 0x55, 0x85, 0x76,
                                          0x24, 0x95, 0xe3, 0x58, 0xf8, 0xa5};
    EXPECT_TRUE(std::memcmp(second_cert_sha1, cert->sha1.data, 20) == 0);

    ASSERT_TRUE(cert->sha256.data);
    ASSERT_EQ(cert->sha256.len, 32);
    unsigned char second_cert_sha256[32] = {0x58, 0x2d, 0xc1, 0xd9, 0x7a, 0x79, 0x0e, 0xf0,
                                            0x4f, 0xe2, 0x56, 0x7b, 0x1e, 0xc8, 0x8c, 0x26,
                                            0xb0, 0x3b, 0xf6, 0xe9, 0x99, 0x37, 0xca, 0xe6,
                                            0xa0, 0xb5, 0x03, 0x97, 0xad, 0x20, 0xbb, 0xf8};
    EXPECT_TRUE(std::memcmp(second_cert_sha256, cert->sha256.data, 32) == 0);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(
        cert->subject,
        "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 3 SHA256 Code "
        "Signing CA");
    EXPECT_STREQ(
        cert->issuer,
        "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For "
        "authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5");
    EXPECT_EQ(cert->not_after, 1702166399);
    EXPECT_EQ(cert->not_before, 1386633600);
    EXPECT_STREQ(
        cert->key,
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl4MeABavLLHSCMTXaJNRYB5x9uJHtNtYTSNiarS/"
        "WhtR96MNGHdou9g2qy8hUNqe8+"
        "dfJ04LwpfICXCTqdpcDU6kDZGgtOwUzpFyVC7Oo9tE6VIbP0E8ykrkqsDoOatTzCHQzM9/"
        "m+bCzFhqghXuPTbPHMWXBySO8Xu+"
        "MS09bty1mUKfS2GVXxxw7hd924vlYYl4x2gbrxF4GpiuxFVHU9mzMtahDkZAxZeSitFTp5lbhTVX0+"
        "qTYmEgCscwdyQRTWKDtrp7aIIx7mXK3/nVjbI13Iwrb2pyXGCEnPIMlF7AVlIASMzT+KV93i/"
        "XE+Q4qITVRrgThsIbnepaON2b2wIDAQAB");
    EXPECT_STREQ(cert->serial, "3d:78:d7:f9:76:49:60:b2:61:7d:f4:f0:1e:ca:86:2a");
    EXPECT_STREQ(cert->sig_alg, "sha256WithRSAEncryption");
    EXPECT_STREQ(cert->sig_alg_oid, "1.2.840.113549.1.1.11");
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");

    ASSERT_TRUE(third_sig->certs);
    ASSERT_TRUE(third_sig->certs->certs);
    ASSERT_EQ(third_sig->certs->count, 4);

    //*******************************************//
    // Test the first signature countersignature //
    ASSERT_TRUE(third_sig->countersigs);
    ASSERT_TRUE(third_sig->countersigs->counters);
    ASSERT_EQ(third_sig->countersigs->count, 1);

    const Countersignature *countersig = third_sig->countersigs->counters[0];

    EXPECT_EQ(countersig->verify_flags, COUNTERSIGNATURE_VFY_VALID);
    EXPECT_STREQ(countersig->digest_alg, "sha256");
    EXPECT_EQ(countersig->sign_time, 1527779085);
    unsigned char first_countersig_digest[32] = {0xea, 0x26, 0x7f, 0x65, 0x17, 0xc1, 0x84, 0x57,
                                                 0x1f, 0x2f, 0x2e, 0x83, 0xf9, 0x6e, 0x75, 0xdf,
                                                 0xcf, 0xcd, 0x57, 0x17, 0xe1, 0xa0, 0xf7, 0x46,
                                                 0x0f, 0xb4, 0x37, 0x6f, 0xe9, 0x64, 0x06, 0xbb};
    ASSERT_TRUE(countersig->digest.data);
    ASSERT_EQ(countersig->digest.len, 32);
    EXPECT_TRUE(std::memcmp(first_countersig_digest, countersig->digest.data, 32) == 0);

    ASSERT_TRUE(countersig->chain);
    EXPECT_EQ(countersig->chain->count, 2);

    authenticode_array_free(auth);
}

TEST(PefileTest, ResultOverview)
{
    initialize_authenticode_parser();

    AuthenticodeArray *auth = parse_authenticode(PE_FILE_1, PE_FILE_1_LEN);
    ASSERT_NE(auth, nullptr);

    ASSERT_EQ(auth->count, 2);
    ASSERT_NE(auth->signatures, nullptr);

    const Authenticode *sig = auth->signatures[0];
    {
        ASSERT_TRUE(sig);
        EXPECT_EQ(sig->verify_flags, AUTHENTICODE_VFY_WRONG_FILE_DIGEST);
        EXPECT_EQ(sig->digest.len, 20);
        EXPECT_STREQ(sig->digest_alg, "sha1");

        EXPECT_STREQ(sig->certs->certs[0]->sig_alg_oid, "1.2.840.113549.1.1.5");
        EXPECT_STREQ(sig->certs->certs[0]->sig_alg, "sha1WithRSAEncryption");

        unsigned char sig_digest[] = {0xD6, 0x43, 0x40, 0x50, 0x56, 0xA4, 0xA1, 0x60, 0x42, 0xD4,
                                      0x79, 0x42, 0xA8, 0xC6, 0xA5, 0x95, 0x24, 0xBD, 0xA6, 0x4A};
        EXPECT_TRUE(std::memcmp(sig->digest.data, sig_digest, sig->digest.len) == 0);

        unsigned char real_file_digest[] = {0x9a, 0xd3, 0x54, 0xc6, 0xd1, 0xd3, 0xe5,
                                            0xe5, 0x8b, 0xc4, 0x7e, 0x1c, 0xd3, 0x80,
                                            0xd1, 0x2b, 0x75, 0xe5, 0x05, 0x1c};

        EXPECT_TRUE(
            std::memcmp(sig->file_digest.data, real_file_digest, sizeof(real_file_digest)) == 0);
    }
    sig = auth->signatures[1];
    {
        ASSERT_TRUE(sig);
        EXPECT_EQ(sig->verify_flags, AUTHENTICODE_VFY_WRONG_FILE_DIGEST);

        EXPECT_STREQ(sig->certs->certs[0]->sig_alg_oid, "1.2.840.113549.1.1.5");
        EXPECT_STREQ(sig->certs->certs[0]->sig_alg, "sha1WithRSAEncryption");

        unsigned char sig_digest[] = {0x75, 0xCA, 0xCD, 0xF5, 0xBE, 0x7B, 0xAE, 0xEC,
                                      0xB8, 0x9C, 0x70, 0xBC, 0x01, 0x34, 0x3F, 0xB7,
                                      0xC9, 0xE8, 0xFD, 0x00, 0x0C, 0xC1, 0x91, 0xF0,
                                      0x8D, 0x2A, 0x99, 0x63, 0x59, 0xD6, 0x17, 0xFE};

        EXPECT_TRUE(std::memcmp(sig->digest.data, sig_digest, sizeof(sig_digest)) == 0);

        unsigned char real_file_digest[] = {0x29, 0xc3, 0x24, 0xac, 0xc3, 0xbd, 0x59, 0x6c,
                                            0xce, 0xbd, 0x28, 0xe7, 0xd8, 0xa8, 0x8b, 0x87,
                                            0xb0, 0x6a, 0x87, 0xf2, 0xfd, 0x1f, 0xc2, 0x81,
                                            0x52, 0x5c, 0xe0, 0xda, 0xe4, 0x2b, 0x46, 0xb3};

        EXPECT_TRUE(
            std::memcmp(sig->file_digest.data, real_file_digest, sizeof(real_file_digest)) == 0);
    }

    authenticode_array_free(auth);
}
