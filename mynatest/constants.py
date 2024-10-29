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
  }
}

COMMON_DF_DATA = {
  "DF": DF("D3921000310001010100"),
  "EFs": {
    "CardID": EF("0001"),
  }
} 