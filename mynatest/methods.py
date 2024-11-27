from tqdm import tqdm, trange
from mynatest.testdata import MESSAGES, MSG2BYLEN
from sc_tools.apdu import CommandApdu
from sc_tools.card_connection import CardConnection
from sc_tools.card_response import CardResponseStatusType
from sc_tools.methods import CardFileAttribute, list_ef

def get_pin_remaining(
    card: CardConnection,
):
  lookup = CommandApdu(0x00, 0x20, 0x00, 0x80)
  _, sw = card.transmit(lookup.to_bytes(), raise_error=False)
  return sw.verification_remaining()

def safe_verify(
    card: CardConnection,
    pin: bytes,
    assert_retry_count: int,
):
  remaining = get_pin_remaining(card)
  if remaining == 0:
    raise ValueError("PIN is blocked")
  if remaining < assert_retry_count:
    raise ValueError("PIN retry count is too low")
  card.verify(pin)

def sign_jpki_messages(
    card: CardConnection,
    msg_lists: list = MESSAGES,
):
  p1p2 = []
  # parameter search phase
  for p1 in trange(0x00, 0x100, desc="p1"):
    # first test with p2=0x00 and p2=0x80
    msg = msg_lists[0]
    _, s00 = card.jpki_sign(msg, p1=p1, p2=0x00, raise_error=False)
    _, s80 = card.jpki_sign(msg, p1=p1, p2=0x80, raise_error=False)
    if s00.status_type() != CardResponseStatusType.NORMAL_END and s80.status_type() != CardResponseStatusType.NORMAL_END:
      continue # assume that this p1 is not valid

    for p2 in trange(0x00, 0x100, desc="p2", leave=False):
      sig, status = card.jpki_sign(msg, p1=p1, p2=p2, raise_error=False)
      if status.status_type() == CardResponseStatusType.NORMAL_END:
        tqdm.write(f"Signature found at {p1.to_bytes(1, 'big').hex()}{p2.to_bytes(1, 'big').hex()}: {len(sig)} bytes")
        p1p2.append((p1, p2))
  
  # sign phase
  for m in tqdm(msg_lists, desc="Messages"):
    for p1, p2 in tqdm(p1p2, desc="P1P2", leave=False):
      _, status = card.jpki_sign(m, p1=p1, p2=p2, raise_error=False)
      if status.status_type() != CardResponseStatusType.NORMAL_END:
        tqdm.write(f"Warning: Signature failed at {p1.to_bytes(1, 'big').hex()}{p2.to_bytes(1, 'big').hex()}")
    


def sign_std_messages(
    card: CardConnection,
    msg_lists: list = MESSAGES,
):
  for p in trange(0x0000, 0xffff, desc="P1P2", leave=False):
    sig, status = card.std_sign(msg_lists[0], p1=(p >> 8) & 0xff, p2=p & 0xff, raise_error=False)
    if status.status_type() == CardResponseStatusType.NORMAL_END:
      tqdm.write(f"Signature found at {p.to_bytes(2, 'big').hex()}: {sig.hex()}")

def sign_std_9e9a_messages(
    card: CardConnection,
    msg_lists: list = MESSAGES,
):
  for m in tqdm(msg_lists, desc="Messages"):
    sig, status = card.std_sign(m, raise_error=False)
    if status.status_type() == CardResponseStatusType.NORMAL_END:
      tqdm.write(f"Signature found at 9E9A: {sig.hex()}")   

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

def make_bytes(length: int) -> bytes:
  return bytes([i % 256 for i in range(length)])

def seek_jpki_sign_ub(
    card: CardConnection,
    start: int = 0xf0,
    end: int = 0xfff,
    p1: int = 0x00,
    p2: int = 0x00,
):
  """
  Seek for the upper bound byte length that JPKI Sign can handle
  Find the maximum length with the binary search algorithm
  """

  while start < end:
    mid = (start + end) // 2
    msg = make_bytes(mid)
    _, status = card.jpki_sign(msg, raise_error=False, p1=p1, p2=p2)
    stt = status.status_type()
    if stt == CardResponseStatusType.NORMAL_END:
      start = mid + 1
    else:
      end = mid
  tqdm.write(f"JPKI Sign can handle {start} bytes")

def test_efs(
    card: CardConnection,
    start: int = 0,
    end: int = 0xffff,
    ignore_error: bool = False,
):
  lief = list_ef(card, start=start, end=end, ignore_error=ignore_error)
  print("Testing Found EFs...")
  for (efid, attr) in tqdm(lief, desc="EFs"):
    try:
      card.select_ef(efid)
    except Exception as e:
      tqdm.write(f"EF {efid.hex()} should not fail. Retrying...")
      card.select_ef(efid)
    tqdm.write(f"EF: {efid.hex()} Attr: {attr.name}")
    if attr == CardFileAttribute.UNKNOWN:
      continue
    if CardFileAttribute.IEF_VERIFY_KEY in attr:
      get_pin_remaining(card)
    if CardFileAttribute.VERIFICATION_REQUIRED in attr:
      continue
    if CardFileAttribute.LOCKED in attr:
      continue
    if CardFileAttribute.WEF_TRANSPARENT in attr:
      card.read_all_binary()
    if CardFileAttribute.WEF_RECORD in attr:
      get_whole_record(card)
      iter_record(card) 
    if CardFileAttribute.IEF_INTERNAL_AUTHENTICATE_KEY in attr:
      intauth_messages(card)
    if CardFileAttribute.JPKI_SIGN_PRIVATE_KEY in attr:
      sign_jpki_messages(card, msg_lists=MESSAGES)
      sign_std_9e9a_messages(card, msg_lists=MESSAGES)
    
  print("Test Finished")