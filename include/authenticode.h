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

#ifndef AUTHENTICODE_PARSER_AUTHENTICODE_H
#define AUTHENTICODE_PARSER_AUTHENTICODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <time.h>

/* Signature is valid */
#define AUTHENTICODE_VFY_VALID            0
/* Parsing error (from OpenSSL functions) */
#define AUTHENTICODE_VFY_CANT_PARSE       1
/* Signers certificate is missing */
#define AUTHENTICODE_VFY_NO_SIGNER_CERT   2
/* No digest saved inside the signature */
#define AUTHENTICODE_VFY_DIGEST_MISSING   3
/* Non verification errors - allocations etc. */
#define AUTHENTICODE_VFY_INTERNAL_ERROR   4
/* SignerInfo part of PKCS7 is missing */
#define AUTHENTICODE_VFY_NO_SIGNER_INFO   5
/* PKCS7 doesn't have type of SignedData, can't proceed */
#define AUTHENTICODE_VFY_WRONG_PKCS7_TYPE 6
/* PKCS7 doesn't have corrent content, can't proceed */
#define AUTHENTICODE_VFY_BAD_CONTENT      7
/* Contained and calculated digest don't match */
#define AUTHENTICODE_VFY_INVALID          8

/* Countersignature is valid */
#define COUNTERSIGNATURE_VFY_VALID                  0
/* Parsing error (from OpenSSL functions) */
#define COUNTERSIGNATURE_VFY_CANT_PARSE             1
/* Signers certificate is missing */
#define COUNTERSIGNATURE_VFY_NO_SIGNER_CERT         2
/* Unknown algorithm, can't proceed with verification */
#define COUNTERSIGNATURE_VFY_UNKNOWN_ALGORITHM      3
/* Verification failed, digest mismatch */
#define COUNTERSIGNATURE_VFY_INVALID                4
/* Failed to decrypt countersignature enc_digest for verification */
#define COUNTERSIGNATURE_VFY_CANT_DECRYPT_DIGEST    5
/* No digest saved inside the countersignature */
#define COUNTERSIGNATURE_VFY_DIGEST_MISSING         6
/* Message digest inside countersignature doesn't match signature it countersigns */
#define COUNTERSIGNATURE_VFY_DOESNT_MATCH_SIGNATURE 7
/* Non verification errors - allocations etc. */
#define COUNTERSIGNATURE_VFY_INTERNAL_ERROR         8
/* Time is missing in the timestamp signature */
#define COUNTERSIGNATURE_VFY_TIME_MISSING           9

typedef struct {
    uint8_t* data;
    int len;
} ByteArray;

typedef struct {
    ByteArray country;
    ByteArray organization;
    ByteArray organizationalUnit;
    ByteArray nameQualifier;
    ByteArray state;
    ByteArray commonName;
    ByteArray serialNumber;
    ByteArray locality;
    ByteArray title;
    ByteArray surname;
    ByteArray givenName;
    ByteArray initials;
    ByteArray pseudonym;
    ByteArray generationQualifier;
    ByteArray emailAddress;
} Attributes;

typedef struct {
    long version;
    char* issuer;
    char* subject;
    char* serial;
    ByteArray sha1;
    ByteArray sha256;
    char* key_alg;
    char* sig_alg;
    time_t not_before;
    time_t not_after;
    char* key;
    Attributes issuer_attrs;
    Attributes subject_attrs;
} Certificate;

typedef struct {
    Certificate** certs;
    size_t count;
} CertificateArray;

typedef struct {
    int verify_flags;
    char* sign_time;
    char* digest_alg;
    ByteArray digest;
    CertificateArray* chain;
} Countersignature;

typedef struct {
    Countersignature** counters;
    size_t count;
} CountersignatureArray;

typedef struct {
    ByteArray digest;
    char* digest_alg; /* name of the digest algorithm */
    char* program_name;
    CertificateArray* chain;
} Signer;

typedef struct {
    int verify_flags;
    int version;
    char* digest_alg; /* name of the digest algorithm */
    ByteArray digest;
    Signer* signer;
    CertificateArray* certs;
    CountersignatureArray* countersigs;
} Authenticode;

typedef struct {
    Authenticode** signatures;
    size_t count;
} AuthenticodeArray;

AuthenticodeArray* authenticode_new(const uint8_t* data, long len);
void authenticode_array_free(AuthenticodeArray* auth);

#ifdef __cplusplus
}
#endif

#endif
