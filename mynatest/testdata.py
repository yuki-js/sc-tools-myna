SHA256_HEADER = bytes.fromhex("30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20")
SHA1_HEADER = bytes.fromhex("30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14")
MD5_HEADER = bytes.fromhex("30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10")
MESSAGES = [
  SHA1_HEADER + bytes.fromhex("fcb9ccab72c3ce591a677d0c12f4a37f6151fa713f75a342bd3731a072a80f44"),
]

def make_bytes(length: int) -> bytes:
  return bytes([i % 256 for i in range(length)])

MSG2BYLEN = [
  
  make_bytes(0x220),
  make_bytes(32),
  SHA256_HEADER + make_bytes(32),
  make_bytes(64),
  make_bytes(65),
  make_bytes(128),
  make_bytes(129),
  make_bytes(256),
  make_bytes(257),
]

SEC_CODE = {
"4000000204421200822020240502": 8150,
}

