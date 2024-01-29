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

#include <stdio.h>
#include <stdlib.h>

#include <authenticode-parser/authenticode.h>

void print_bytes(const ByteArray *bytes)
{
    if (bytes->data) {
        for (int i = 0; i < bytes->len; ++i) {
            printf("%02x", bytes->data[i]);
        }
        puts("");
    } else {
        puts("(null)");
    }
}

void print_certificate(Certificate *cert, char *indent)
{
    printf("%sVersion             : %ld\n", indent, cert->version);
    printf("%sSubject             : %s\n", indent, cert->subject);
    printf("%sIssuer              : %s\n", indent, cert->issuer);
    printf("%sSerial              : %s\n", indent, cert->serial);
    printf("%sNot After           : %lu\n", indent, cert->not_after);
    printf("%sNot Before          : %lu\n", indent, cert->not_before);
    printf("%sSHA1                : ", indent);
    print_bytes(&cert->sha1);

    printf("%sSHA256              : ", indent);
    print_bytes(&cert->sha256);

    printf("%sKey Algorithm       : %s\n", indent, cert->key_alg);
    printf("%sSignature Algorithm : %s\n", indent, cert->sig_alg);
    printf("%sPublic key          : %s\n", indent, cert->key);
}

void print_authenticode(Authenticode *auth)
{
    char *indent = "    ";

    printf("%sPKCS7 Signature:\n", indent);

    indent = "      ";

    printf("%sVersion           : %d\n", indent, auth->version);
    printf("%sDigest            : ", indent);
    print_bytes(&auth->digest);
    printf("%sFile Digest       : ", indent);
    print_bytes(&auth->file_digest);
    printf("%sDigest Algorithm  : %s\n", indent, auth->digest_alg);
    printf("%sVerify flags      : %d\n", indent, auth->verify_flags);
    if (auth->signer->program_name) {
        printf("%sProgram name      : %s\n", indent, auth->signer->program_name);
    }
    printf("\n");

    if (auth->certs) {
        printf("%sCertificate count : %ld\n", indent, auth->certs->count);
        printf("%sCertificates: \n\n", indent);

        for (size_t i = 0; i < auth->certs->count; ++i) {
            char *indent = "        ";

            printf("%sCertificate %lu:\n", indent, i);
            print_certificate(auth->certs->certs[i], "              ");
        }
    }

    if (auth->signer) {
        printf("%sSigner Info:\n", indent);

        char *indent = "        ";

        printf("%sDigest       : ", indent);
        print_bytes(&auth->signer->digest);
        printf("%sDigest Algo  : %s\n", indent, auth->signer->digest_alg);
        printf("%sProgram name : %s\n", indent, auth->signer->program_name);

        if (auth->signer->chain) {
            printf("%sChain size   : %lu\n", indent, auth->signer->chain->count);
            printf("%sChain:\n", indent);

            for (size_t i = 0; i < auth->signer->chain->count; ++i) {
                char *indent = "            ";

                printf("%sCertificate %lu:\n", indent, i);
                print_certificate(auth->signer->chain->certs[i], "                ");
            }
        }
    }

    puts("\n");

    if (auth->countersigs) {
        for (size_t i = 0; i < auth->countersigs->count; ++i) {
            Countersignature *counter = auth->countersigs->counters[i];
            printf("%sCountersignature:\n", indent);
            char *indent = "        ";

            printf("%sDigest           : ", indent);
            print_bytes(&counter->digest);
            printf("%sDigest Algorithm : %s\n", indent, counter->digest_alg);
            printf("%sSigning Time     : %lu\n", indent, counter->sign_time);
            printf("%sVerify flags     : %d\n", indent, counter->verify_flags);

            if (counter->chain) {
                printf("%sChain size       : %lu\n", indent, counter->chain->count);
                printf("%sChain:\n", indent);

                for (size_t i = 0; i < counter->chain->count; ++i) {
                    char *indent = "            ";

                    printf("%sCertificate %lu:\n", indent, i);
                    print_certificate(counter->chain->certs[i], "                ");
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Missing file argument\n");
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        printf("File not found.\n");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *data = malloc(fsize);
    if (!data) {
        printf("Allocation failure.\n");
        return 1;
    }

    fread(data, 1, fsize, fp);
    fclose(fp);
    /* initialize all global openssl objects */
    initialize_authenticode_parser();
    AuthenticodeArray *auth = parse_authenticode(data, fsize);
    if (!auth) {
        printf("Couldn't parse any signatures.\n");
        return 0;
    }

    printf("Signature count: %lu\n", auth->count);
    printf("Signatures: %lu\n", auth->count);

    for (size_t i = 0; i < auth->count; ++i)
        print_authenticode(auth->signatures[i]);

    authenticode_array_free(auth);
    free(data);

    return 0;
}
