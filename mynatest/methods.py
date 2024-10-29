from tqdm import tqdm, trange
from mynatest.testdata import MESSAGES
from sc_tools.apdu import CommandApdu
from sc_tools.card_connection import CardConnection
from sc_tools.card_response import CardResponseStatusType
from sc_tools.methods import CardFileAttribute, list_ef


def safe_verify(
    card: CardConnection,
    pin: bytes,
    assert_retry_count: int,
):
  lookup = CommandApdu(0x00, 0x20, 0x00, 0x80)
  _, sw = card.transmit(lookup.to_bytes(), raise_error=False)
  remaining = sw.sw & 0x000F
  if remaining == 0:
    raise ValueError("PIN is blocked")
  if remaining < assert_retry_count:
    raise ValueError("PIN retry count is too low")
  card.verify(pin)

def sign_jpki_messages(
    card: CardConnection,
):
  for msg in MESSAGES:
    # for p in tqdm(range(0x0000, 0xffff)):
    #   p1 = (p >> 8) & 0xff
    #   p2 = p & 0xff
    #   sig, status = card.jpki_sign(msg, p1=p1, p2=p2, raise_error=False)
    for p1 in trange(0x00, 0xff):
      # first test with p2=0x00
      sig, status = card.jpki_sign(msg, p1=p1, p2=0x00, raise_error=False)
      if status.status_type() != CardResponseStatusType.NORMAL_END:
        continue # assume that p2=0x00 has no child signature

      for p2 in trange(0x00, 0xff):
        sig, status = card.jpki_sign(msg, p1=p1, p2=p2, raise_error=False)
        if status.status_type() == CardResponseStatusType.NORMAL_END:
          tqdm.write(f"Signature found at {p1.to_bytes(1, 'big').hex()}{p2.to_bytes(1, 'big').hex()}: {sig.hex()}")


def sign_std_messages(
    card: CardConnection,
):
  for msg in MESSAGES:
    for p in tqdm(range(0x0000, 0xffff)):
      sig, status = card.std_sign(msg, p1=(p >> 8) & 0xff, p2=p & 0xff, raise_error=False)
      if status.status_type() == CardResponseStatusType.NORMAL_END:
        tqdm.write(f"Signature found at {p.to_bytes(2, 'big').hex()}: {sig.hex()}")

def intauth_messages(
    card: CardConnection,
):
  for msg in MESSAGES:
    card.internal_authenticate(msg)


def iter_record(
    card: CardConnection,
):
  for i in tqdm(range(0, 0xff)):
    data, sw = card.transmit(CommandApdu(0x00, 0xb2, i, 0x04, None, "max").to_bytes(), raise_error=False)
    if sw == 0x9000:
      print(f"Record {i}: {data.hex()}")

def get_whole_record(
    card: CardConnection,
):
  return card.transmit(CommandApdu(0x00, 0xb2, 1, 0x05, None, "max").to_bytes(), raise_error=True)[0]


def test_efs(
    card: CardConnection,
    start: int = 0,
    end: int = 0xffff
):
  lief = list_ef(card, start=start, end=end)
  print("Testing Found EFs...")
  for (efid, attr) in lief:
    card.select_ef(efid)
    if attr == CardFileAttribute.UNKNOWN:
      continue
    if CardFileAttribute.IEF_VERIFY_KEY in attr:
      pass # 無視
    if CardFileAttribute.VERIFICATION_REQUIRED in attr:
      continue
    if CardFileAttribute.LOCKED in attr:
      continue
    if CardFileAttribute.WEF_TRANSPARENT in attr:
      card.read_all_binary()
    if CardFileAttribute.WEF_RECORD in attr:
      get_whole_record(card)
      iter_record(card) # 時間かかるのでコメントアウト
    if CardFileAttribute.IEF_INTERNAL_AUTHENTICATE_KEY in attr:
      intauth_messages(card)
    if CardFileAttribute.JPKI_SIGN_PRIVATE_KEY in attr:
      sign_jpki_messages(card) # 時間かかるのでコメントアウト
      pass
    
  print("Test Finished")