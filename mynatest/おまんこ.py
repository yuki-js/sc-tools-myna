
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
filename = f"transceive_logs/transceive_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
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

repower_card()

print("---------- Kenkaku Phase -----------")
card.select_df(KENKAKU_DATA["DF"].df)
card.select_ef(bytes.fromhex("0011"))
safe_verify(card, b"120502",0xa)
card.select_ef(KENKAKU_DATA["EFs"]["PIN-A-EF"].ef)
safe_verify(card, b"977483806896",0xa)
test_efs(card, 0, 0x30, ignore_error=True)


print("-------------- Finalization --------------")
print("Test has Finished!")
transceive_log_file.close()