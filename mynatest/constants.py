from .entity import DF, EF, Tag
# JPKIパート
JPKI_DATA = {
  "DF": DF("D392F000260100000001"),
  "Token": EF("0006", is_transparent=True),
  "Sign": {
    "CertEF": EF("0001", is_transparent=True, is_der=True, is_x509=True, need_verify=True),
    "CertCAEF": EF("0002", is_transparent=True, is_der=True, is_x509=True),
    "PINEF": EF("001B", is_pin=True, pin_retry_count=5),
    "KeyEF": EF("001A", is_jpki_key=True, need_verify=True),
  },
  "Auth": {
    "CertEF": EF("000A", is_transparent=True, is_der=True, is_x509=True, need_verify=False),
    "CertCAEF": EF("000B", is_transparent=True, is_der=True, is_x509=True),
    "PINEF": EF("0018", is_pin=True, pin_retry_count=3),
    "KeyEF": EF("0017", is_jpki_key=True, need_verify=True),
  },

  "UnknownEF": EF("0008", is_transparent=True),  # 3バイトだけの謎のEF
  "Pinless": {
    "UnknownEF": EF("0016"),  # チェーン証明書をロードする前にselectされるが…
    "IntermediateCert": bytes.fromhex("7F 21 82 02 33 5F 4E 82 01 29 39 32 30 30 30 37 33 08 05 30 30 31 30 30 30 30 39 32 39 39 37 37 34 08 05 30 30 31 30 30 30 30 90 03 01 00 01 91 82 01 00 E1 88 6D ED C3 A7 77 40 2A 8C 1D 9B DC 86 B5 47 EE 9E 7D BE 97 F9 91 E2 1C AE 96 FE 01 88 76 FD 8C 3A F7 0E 76 B5 AA B5 AC 93 D8 C3 CD A8 72 23 10 67 8A 98 49 34 C5 CF 5F AF E6 41 E2 14 F2 09 C5 77 51 E7 BA 33 E5 98 CB 4F FF A4 FD FF 75 C6 E9 FA 81 D0 EA 9F E0 B3 9D 69 61 BE 62 AC 41 11 33 A0 DE 97 40 62 4C F5 2C A7 39 83 04 E3 00 BA B7 B7 3C 00 D1 77 02 AE 0B AE 65 BC A7 0F 98 63 C2 10 84 7A 43 07 9D 5F 0B BC DD 75 14 10 96 59 AC DB 03 B8 76 BA 84 9A AB AA 6A FB 5F 08 88 F4 EB 49 B8 78 4D A3 94 8A 5E 78 4C D2 A5 F1 02 9F 0D 28 E0 6B A3 BA 06 EA 6E B3 1C FB BF D2 E0 F8 4F 51 94 95 A5 F8 71 58 80 8E 7E 44 92 E0 A8 EE B3 96 A1 35 08 19 E9 A1 85 83 88 67 7E 06 87 61 05 E9 AF E8 37 C4 EB B8 14 41 24 76 A4 1C 83 69 F0 31 F6 31 30 59 AF A1 53 35 88 38 83 B5 9F 75"),
    "IntermediateCertSig": bytes.fromhex("5F 37 82 01 00 BC 5D C2 AF F5 F1 DA 89 CE C0 1D 20 25 4F 71 F0 9F 9E 6A AF C7 9A B5 D9 3C 30 8E 98 A2 BD F5 75 29 FC C6 93 27 B3 26 B1 0E 29 A9 2F 81 0E 40 F1 55 9F F1 D1 BA D8 6A 6E B7 79 CE E2 1D C7 83 F6 5C 46 81 53 83 92 7F 3F 63 D1 45 02 6C C1 FF F9 C9 16 2D 69 7E 1F 4A 6C E5 DC 5C 00 90 91 D0 3F 4F 4B A6 26 AF 42 64 99 21 EF AB A6 71 D6 FE 2C D7 79 DA 1B B8 7C 5C F1 2E 40 6C EE DC 35 2C 51 4C 36 83 B1 C1 2D 31 DE 33 1E 9E 4D 45 73 23 E9 53 A3 7D A9 5E B2 8A EC C3 89 01 96 C8 2F 4A 70 3E E4 63 87 DB C5 50 A7 C0 74 88 90 98 05 C7 A3 5C C5 F9 D5 E0 A7 97 CD E1 CB C2 99 04 8C 0F 4A 58 65 57 43 39 B9 42 E7 E6 82 8D 55 CF 37 06 62 BC CC B9 9F D8 9F 06 93 4E 93 EA A2 AD A8 35 61 8E 6D 97 80 A7 19 3E B5 6F 30 B8 A0 B4 06 B3 80 81 CB F1 23 C5 5E 68 41 2E 6C AD 89 BC 48 71 55")
  }
  
}

# デフォルトDFパート
DEFAULT_DF_DATA = {
  "DOs": {
    "CityId": Tag("F0"),
    "Expiry": Tag("F2"),
    # "CIN": EF("F3"), # たぶん
  }
}

# 券面事項入力補助パート
KENHOJO_DATA = {
  "DF": DF("D3921000310001010408"),
  "EFs": {
    "ApBasicInfoEF": EF("0005"),
    "PINEF": EF("0011",is_pin=True, pin_retry_count=3),
    "InternalAuthKey": EF("0013", is_jpki_key=True),
    "InternalAuthCert": EF("0007", is_transparent=True, is_der=True),
    "Mynumber": EF("0001"),
    "BasicFour": EF("0002"),  # contian Field named"DF", Name, Addres, Birth, Gender
    "Unknown": EF("0003"),  # 4情報ハッシュと署名がある？
    "DataVerificationCert": EF("0004"),  # tag 7f21 中間証明書的な？
    "Unknown2": EF("0006"),  # 何かの公開鍵
  },
}

KENKAKU_DATA = {
  "DF": DF("D3921000310001010402"),
  "EFs": {
    "PIN-A-EF": EF("0013", is_pin=True, pin_retry_count=3),
    "PIN-B-EF": EF("0012", is_pin=True, pin_retry_count=3),
  }
}

COMMON_DF_DATA = {
  "DF": DF("D3921000310001010100"),
  "EFs": {
    "CardID": EF("0001"),
  }
} 

JUKI_DATA = {
  "DF": DF("D3921000310001010401"),
  "EFs": {
    "PIN-EF": EF("001C", is_pin=True, pin_retry_count=3),
  }
}