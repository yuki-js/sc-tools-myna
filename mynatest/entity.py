class EF:
  def __init__(
      self,
      efstr: str,
      is_pin: bool = False,
      is_transparent: bool = False,
      need_verify: bool = False,
      need_external_auth: bool = False,
      is_jpki_key: bool = False,
      is_der: bool = False,
      is_compact_cert: bool = False,
      pin_retry_count: int = 0,
      is_x509: bool = False,
  ):
    ef = bytes.fromhex(efstr)
    # check length
    if len(ef) != 2:
      raise ValueError("Invalid EF string")
    self.ef = ef
    
class DF:
  def __init__(self, dfstr: str):
    df = bytes.fromhex(dfstr)
    # check length
    if len(df) < 5:
      raise ValueError("Invalid DF string")
    
    self.df = df

class Tag:
  def __init__(self, tagstr: str):
    tag = bytes.fromhex(tagstr)
    # check length
    if len(tag) != 1 and len(tag) != 2:
      raise ValueError("Invalid Tag string")
    self.tag = tag