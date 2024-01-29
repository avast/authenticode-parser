import sys
import pefile


# Function to dump the signature from a PE file for tests
def dump_signature(path: str):
    pe = pefile.PE(path)
    security_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    win_certificate = pe.__data__[
        security_directory.VirtualAddress
        + 8 : security_directory.VirtualAddress
        + security_directory.Size
    ]  # Extract WIN_CERTIFICATE
    with open("dump.pkcs7.der", "wb") as fp:
        fp.write(win_certificate)


# Use the function
file_path = sys.argv[1]
# To convert to ASCII PEM to use in tests, use
# openssl pkcs7 -inform der -in dump.pkcs7.der -out sig.pem
