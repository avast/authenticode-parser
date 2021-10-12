#include "../../src/certificate.h"
#include "../data.h"

#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

TEST(CertificateModule, certificate_array_move)
{
    CertificateArray array1 = {.certs = nullptr, .count = 0};

    CertificateArray array2 = {.certs = nullptr, .count = 0};

    Certificate cert1 = {0};
    Certificate cert2 = {0};

    array2.count = 2;
    array2.certs = (Certificate **)malloc(sizeof(Certificate *) * 2);

    array2.certs[0] = &cert1;
    array2.certs[1] = &cert2;

    int res = certificate_array_move(&array1, &array2);
    EXPECT_EQ(res, 0);

    ASSERT_TRUE(array1.certs);
    ASSERT_EQ(array1.count, 2);

    EXPECT_EQ(array1.certs[0], &cert1);
    EXPECT_EQ(array1.certs[1], &cert2);

    EXPECT_EQ(array2.count, 0);
    EXPECT_FALSE(array2.certs);
}

TEST(CertificateModule, certificate_new)
{
    BIO *bio = BIO_new(BIO_s_mem());
    ASSERT_TRUE(bio);

    BIO_write(bio, CERTIFICATE_PEM, std::strlen(CERTIFICATE_PEM));

    X509 *x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    ASSERT_TRUE(x509);

    Certificate *cert = certificate_new(x509);
    ASSERT_TRUE(cert);

    EXPECT_EQ(cert->version, 2);
    EXPECT_STREQ(cert->serial, "38:63:de:f8");
    EXPECT_EQ(cert->not_before, 946057851);
    EXPECT_EQ(cert->not_after, 1879596912);
    EXPECT_STREQ(cert->key_alg, "rsaEncryption");
    EXPECT_STREQ(cert->sig_alg, "sha1WithRSAEncryption");
    EXPECT_STREQ(
        cert->issuer,
        "/O=Entrust.net/OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.)/OU=(c) 1999 "
        "Entrust.net Limited/CN=Entrust.net Certification Authority (2048)");
    EXPECT_STREQ(
        cert->subject,
        "/O=Entrust.net/OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.)/OU=(c) 1999 "
        "Entrust.net Limited/CN=Entrust.net Certification Authority (2048)");

    uint8_t sha1[20] = {0x50, 0x30, 0x06, 0x09, 0x1D, 0x97, 0xD4, 0xF5, 0xAE, 0x39,
                        0xF7, 0xCB, 0xE7, 0x92, 0x7D, 0x7D, 0x65, 0x2D, 0x34, 0x31};

    ASSERT_TRUE(cert->sha1.data);
    ASSERT_EQ(cert->sha1.len, 20);
    EXPECT_TRUE(std::memcmp(cert->sha1.data, sha1, 20) == 0);

    X509_free(x509);
    certificate_free(cert);
}