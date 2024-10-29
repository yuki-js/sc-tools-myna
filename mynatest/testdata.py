SHA256_HEADER = bytes.fromhex("30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20")
SHA1_HEADER = bytes.fromhex("30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14")
MD5_HEADER = bytes.fromhex("30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10")
MESSAGES = [
  bytes.fromhex("aabbccdd"), 
  SHA256_HEADER + bytes.fromhex("eeff0011"),
  SHA1_HEADER + bytes.fromhex("eeff0011"),
  SHA256_HEADER,
  MD5_HEADER,
  bytes.fromhex("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
  SHA1_HEADER + bytes.fromhex("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
]

SEC_CODE = {
"4000000204421200822020240502": 8150,
}