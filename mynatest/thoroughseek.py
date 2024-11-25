
import datetime
from textwrap import dedent
import time

import smartcard
from tqdm import tqdm, trange
from mynatest.constants import COMMON_DF_DATA, JPKI_DATA, JUKI_DATA, KENHOJO_DATA, KENKAKU_DATA
from mynatest.methods import get_whole_record, iter_record, make_bytes, safe_verify, sign_std_messages, test_efs
from mynatest.testdata import MESSAGES
from sc_tools.apdu import CommandApdu
from sc_tools.dump_binary import dump_binary
from sc_tools.card_response import CardResponseStatus, CardResponseStatusType
from sc_tools.card_connection import create_card_connection
from sc_tools.methods import (
    CardFileAttribute,
    list_cla_ins,
    list_p1_p2,
    list_ef,
    list_do,
    search_df,
)
from sc_tools.readers import (
    list_contact_reader,
    connect_with_contact,
    list_contactless_reader,
    connect_contactless,
)
reader_num=0

reader = connect_with_contact(reader_num)
atr = reader.getATR()

card = create_card_connection(
    reader,
    auto_get_response=True,
    allow_extended_apdu=True,
)

# get command arguments from command line
import sys
filename = "transceive.log"
if len(sys.argv) > 1:
    filename = sys.argv[1]

transceive_log_file = open(filename, "a")
def transmit_callback(
    command: bytes,
    response_data: bytes,
    response_status: CardResponseStatus,
) -> None:
    now = datetime.datetime.now().isoformat()
    command_hex = command.hex(" ").upper()
    response_data += response_status.sw.to_bytes(length=2, byteorder="big")
    response_data_hex = response_data.hex(" ").upper()
    sw_hex = format(response_status.sw, "04X")
    response_status_type = response_status.status_type().name
    transceive_log = """
        [{now}]
        < {command_hex}
        > {response_data_hex}
        SW: 0x{sw_hex} ({response_status_type})

    """
    transceive_log_file.write(
        dedent(transceive_log)[1:].format(
            now=now,
            command_hex=command_hex,
            response_data_hex=response_data_hex,
            sw_hex=sw_hex,
            response_status_type=response_status_type,
        )
    )
    transceive_log_file.flush()

card.transmit_callback = transmit_callback

#write atr to file
transceive_log_file.write(f"ATR: {atr}\n\n")

def repower_card():
    reader.reconnect(disposition=smartcard.scard.SCARD_UNPOWER_CARD)

print("-------------- Default DF Phase --------------")
repower_card()
iin, _ = card.get_data(b"\x42")
cin, _ = card.get_data(b"\x45")
card_data, _ = card.get_data(b"\x66")
print(f"IIN: {iin.hex()}")
print(f"CIN: {cin.hex()}")
print(f"Card Data: {card_data.hex()}")

repower_card()
list_do(card)

repower_card()
list_cla_ins(card)

repower_card()
test_efs(card, 0, 0x30, ignore_error=True)
test_efs(card, 0x2f00, 0x2fff, ignore_error=True)

# Common DF
print("-------------- Common DF Phase --------------")

repower_card()

card.select_df(COMMON_DF_DATA["DF"].df)
card.select_ef(b"\x00\x01")
card_id = get_whole_record(card)[2:]
print(f"Card ID: {card_id.decode('ascii')}")
test_efs(card, 0, 0x30, ignore_error=True)
test_efs(card, 0x2f00, 0x2fff, ignore_error=True)

list_do(card)

print("-------------- JPKI Phase --------------")

repower_card()
card.select_df(JPKI_DATA["DF"].df)
card.select_ef(JPKI_DATA["Token"].ef)
token, status=card.read_binary()
if status.status_type() != CardResponseStatusType.NORMAL_END:
    print("Failed to read Token")
    exit(1)

list_do(card)
card.select_ef(JPKI_DATA["Sign"]["PINEF"].ef)
prompted_sign_pin = input("Enter Sign PIN: ")
if len(prompted_sign_pin) > 5:
    safe_verify(card, prompted_sign_pin.encode("ascii"), 5)
else: 
    print("PIN is too short. Skipping verification")
card.select_ef(JPKI_DATA["Auth"]["PINEF"].ef)
prompted_auth_pin = input("Enter Auth PIN: ")
safe_verify(card, prompted_auth_pin.encode("ascii"), 3)

card.transmit(CommandApdu(0x00, 0x84, 0x00, 0x00, None, 0x100).to_bytes())
_, sw = card.transmit(CommandApdu(0x00, 0x84, 0x00, 0x00, None, 0x101).to_bytes(), raise_error=False)
assert sw.sw != 0x9000


card.select_ef(JPKI_DATA["Pinless"]["UnknownEF"].ef)
card.transmit(CommandApdu(0x80, 0xa2, 0x06, 0xc1, JPKI_DATA["Pinless"]["IntermediateCert"], 0x00, True).to_bytes())
_, sw = card.transmit(CommandApdu(0x80, 0xa2, 0x00, 0xc1, JPKI_DATA["Pinless"]["IntermediateCertSig"], 0x00, True).to_bytes(), raise_error=False)
if sw.sw != 0x9000:
    print("This card does not support such IntermediateCertSig")


test_efs(card, 0, 0x30, ignore_error=True)
test_efs(card, 0x2f00, 0x2fff, ignore_error=True)

card.select_ef(JPKI_DATA["Auth"]["KeyEF"].ef)
sign_std_messages(card)


print("-------------- Kenhojo Phase --------------")
repower_card()

card.select_df(KENHOJO_DATA["DF"].df)
card.select_ef(KENHOJO_DATA["EFs"]["PINEF"].ef)
prompted_kenhojo_pin = input("Enter Kenhojo PIN: ")
safe_verify(card, prompted_kenhojo_pin.encode("ascii"), 3)
test_efs(card, 0, 0x30, ignore_error=True)
test_efs(card, 0x2f00, 0x2fff, ignore_error=True)

list_do(card)
card.select_ef(KENHOJO_DATA["EFs"]["Mynumber"].ef)
data, sw = card.read_binary()
assert sw.sw == 0x9000
myna=data[3:15].decode("ascii")
print(f"My Number: {myna}")

print("---------- Kenkaku Phase -----------")
card.select_df(KENKAKU_DATA["DF"].df)
card.select_ef(KENKAKU_DATA["EFs"]["PIN-A-EF"].ef)
safe_verify(card, myna.encode("ascii"), 10)
test_efs(card, 0, 0x30, ignore_error=True)
test_efs(card, 0x2f00, 0x2fff, ignore_error=True)
list_do(card)

print("-------------- Juki Phase --------------")
repower_card()
card.select_df(JUKI_DATA["DF"].df)

card.select_ef(JUKI_DATA["EFs"]["PIN-EF"].ef)
prompted_kenhojo_pin = input("Enter Juki PIN: ")
safe_verify(card, prompted_kenhojo_pin.encode("ascii"), 3)

test_efs(card, 0, 0x30, ignore_error=True)
test_efs(card, 0x2f00, 0x2fff, ignore_error=True)

print("-------------- Extra JPKI Phase --------------")

def prepare_sign_fn():
    try:
        repower_card()
        card.select_df(JPKI_DATA["DF"].df)
        card.select_ef(JPKI_DATA["Sign"]["PINEF"].ef)
        safe_verify(card, prompted_sign_pin.encode("ascii"), 5)
        card.select_ef(JPKI_DATA["Sign"]["KeyEF"].ef)
    except Exception as e:
        # wait one second and retry
        tqdm.write(f"Retry occured: {e}")
        time.sleep(1)
        prepare_sign_fn()

def prepare_auth_fn():
    try:
        repower_card()
        card.select_df(JPKI_DATA["DF"].df)
        card.select_ef(JPKI_DATA["Auth"]["PINEF"].ef)
        safe_verify(card, prompted_auth_pin.encode("ascii"), 3)
        card.select_ef(JPKI_DATA["Auth"]["KeyEF"].ef)
    except Exception as e:
        # wait one second and retry
        tqdm.write(f"Retry occured: {e}")
        time.sleep(1)
        prepare_auth_fn()

def find_p1p2(prepfn):
    p1p2 = []
    # parameter search phase
    for p1 in trange(0x00, 0x10, desc="p1", leave=False):
        # first test with p2=0x00 and p2=0x80
        msg = MESSAGES[0]
        for p2 in tqdm([0x00, 0x80, 0x97, 0x9a], desc="p2", leave=False):
            prepfn()
            sig, status = card.jpki_sign(msg, p1=p1, p2=p2, raise_error=False)
            if status.status_type() == CardResponseStatusType.NORMAL_END:
                tqdm.write(f"Signature found at {p1.to_bytes(1, 'big').hex()}{p2.to_bytes(1, 'big').hex()}: {len(sig)} bytes")
                p1p2.append((p1, p2))
    return p1p2

p1p2_auth = find_p1p2(prepare_auth_fn)
p1p2_sign = find_p1p2(prepare_sign_fn)

def seek_jpki_sign_ub(
    prepfn,
    start: int = 0xf0,
    end: int = 0xffff,
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
    prepfn()
    _, status = card.jpki_sign(msg, raise_error=False, p1=p1, p2=p2)
    stt = status.status_type()
    if stt == CardResponseStatusType.NORMAL_END:
      start = mid + 1
    else:
      end = mid
  tqdm.write(f"JPKI Sign can handle {start} bytes")

def seek_by_p1p2(prepfn, p1p2):
    for p1, p2 in tqdm(p1p2, desc="P1P2(Test)", leave=False):
        try:
            seek_jpki_sign_ub(prepfn, p1=p1, p2=p2)
        except Exception as e:
            tqdm.write(f"Failed to seek at {p1.to_bytes(1, 'big').hex()}{p2.to_bytes(1, 'big').hex()}: {e}")

seek_by_p1p2(prepare_sign_fn, p1p2_sign)
seek_by_p1p2(prepare_auth_fn, p1p2_auth)

print("-------------- Finalization --------------")
print("Test has Finished!")
transceive_log_file.close()