"""Convert hex string like c7fef94e329bd9b66b281539265f989313356cbd9c345df9e670e9c4b6e0edce to C array init"""
import sys


def hex_to_c_array(hex_string: str) -> str:
    # Split the hex string into bytes
    bytes = [hex_string[i : i + 2] for i in range(0, len(hex_string), 2)]

    # Format the bytes as a C array
    c_array = ", ".join("0x" + byte for byte in bytes)
    c_array = "uint8_t array[] = {" + c_array + "};"

    return c_array


# Use the function
hex_string = sys.argv[1]
print(hex_to_c_array(hex_string))
