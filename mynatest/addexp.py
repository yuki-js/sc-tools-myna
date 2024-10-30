
import datetime
from textwrap import dedent

from tqdm import tqdm
from mynatest.constants import COMMON_DF_DATA, JPKI_DATA, JUKI_DATA, KENHOJO_DATA, KENKAKU_DATA
from mynatest.methods import get_whole_record, iter_record, safe_verify, sign_std_messages, test_efs
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



print("-------------- Default DF Phase --------------")
iin, _ = card.get_data(b"\x42")
cin, _ = card.get_data(b"\x45")
card_data, _ = card.get_data(b"\x66")
print(f"IIN: {iin.hex()}")
print(f"CIN: {cin.hex()}")
print(f"Card Data: {card_data.hex()}")

#list_do(card)

#list_cla_ins(card)
#test_efs(card, 0, 0x10000, ignore_error=True)

# Common DF
print("-------------- Common DF Phase --------------")

card.select_df(COMMON_DF_DATA["DF"].df)
card.select_ef(b"\x00\x01")
card_id = get_whole_record(card)[2:]
print(f"Card ID: {card_id.decode('ascii')}")
#test_efs(card, 0, 0x10000, ignore_error=True)

#list_do(card)

print("-------------- JPKI Phase --------------")

card.select_df(JPKI_DATA["DF"].df)
card.select_ef(JPKI_DATA["Token"].ef)
token, status=card.read_binary()
if status.status_type() != CardResponseStatusType.NORMAL_END:
    print("Failed to read Token")
    exit(1)

card.select_ef(JPKI_DATA["Sign"]["PINEF"].ef)
safe_verify(card, b"ABC123", 5)
card.select_ef(JPKI_DATA["Auth"]["PINEF"].ef)
safe_verify(card, b"1234", 3)

test_efs(card, 0x00, 0xff, ignore_error=True)

test_efs(card, 0x2f00, 0x2fff, ignore_error=True)

card.select_ef(JPKI_DATA["Auth"]["KeyEF"].ef)


print("-------------- Kenhojo Phase --------------")

card.select_df(KENHOJO_DATA["DF"].df)
card.select_ef(KENHOJO_DATA["EFs"]["PINEF"].ef)
safe_verify(card, b"1234", 3)
test_efs(card, 0x2f00, 0x2fff, ignore_error=True)

card.select_ef(KENHOJO_DATA["EFs"]["Mynumber"].ef)
data, sw = card.read_binary()
assert sw.sw == 0x9000
myna=data[3:15].decode("ascii")
print(f"My Number: {myna}")

print("Kenkaku Phase")
card.select_df(KENKAKU_DATA["DF"].df)
card.select_ef(KENKAKU_DATA["EFs"]["PIN-A-EF"].ef)
safe_verify(card, myna.encode("ascii"), 10)
test_efs(card, 0x2f00, 0x2fff, ignore_error=True)

print("-------------- Juki Phase --------------")
card.select_df(JUKI_DATA["DF"].df)

card.select_ef(JUKI_DATA["EFs"]["PIN-EF"].ef)
safe_verify(card, b"1234", 3)

test_efs(card, 0x00, 0xff, ignore_error=True)
test_efs(card, 0x2f00, 0x2fff, ignore_error=True)

print("Finished")
transceive_log_file.close()