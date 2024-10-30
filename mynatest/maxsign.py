
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
transceive_log_file = open("transceive.log", "a")
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



print("-------------- Extra JPKI Phase --------------")

def prepare_sign_fn():
    try:
        reader.reconnect(disposition=smartcard.scard.SCARD_UNPOWER_CARD)
        card.select_df(JPKI_DATA["DF"].df)
        card.select_ef(JPKI_DATA["Sign"]["PINEF"].ef)
        safe_verify(card, b"ABC123", 5)
        card.select_ef(JPKI_DATA["Sign"]["KeyEF"].ef)
    except Exception as e:
        # wait one second and retry
        tqdm.write(f"Retry occured: {e}")
        time.sleep(1)
        prepare_sign_fn()

def prepare_auth_fn():
    try:
        reader.reconnect(disposition=smartcard.scard.SCARD_UNPOWER_CARD)
        card.select_df(JPKI_DATA["DF"].df)
        card.select_ef(JPKI_DATA["Auth"]["PINEF"].ef)
        safe_verify(card, b"1234", 3)
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
    end: int = 0x1fff,
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
        seek_jpki_sign_ub(prepfn, p1=p1, p2=p2)

seek_by_p1p2(prepare_sign_fn, p1p2_sign)
seek_by_p1p2(prepare_auth_fn, p1p2_auth)
    
print("Finished")
transceive_log_file.close()