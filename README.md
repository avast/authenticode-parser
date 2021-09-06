# Authenticode parser
Authenticode parser is a tool, written in C, that analyzes Authenticode signatures using OpenSSL.

Input of this tool is binary data containing Authenticode signature. Parser then attempts to retrieve most of the valuable information (digest, countersignature, nested signatures, ...), verify their static values (matching calculated digest with encrypted digest, etc. except certificate chain verification) and exports this information into a C structure.

## License

Copyright (c) 2021 Avast Software, licensed under the MIT license. See the LICENSE file for more details.