"""APDU"""

from typing import Literal

LeLiteral = Literal["max"]


def max_lc_le(extended_apdu: bool) -> int:
    """Get Max Lc/Le value

    Returns:
        int: Max Lc/Le value
    """

    return 0x10000 if extended_apdu else 0x100


class CommandApdu:
    """Command APDU"""

    def __init__(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes | None = None,
        le: int | LeLiteral = 0x00,
        extended: bool = True,
    ) -> None:
        """Constructor

        Args:
            cla (int): CLA
            ins (int): INS
            p1 (int): P1
            p2 (int): P2
            data (bytes | None, optional): Data. Defaults to None.
            le (int | LeLiteral, optional): Le. Defaults to 0x00.
            extended (bool, optional): Is extended. Defaults to True.
        """

        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data if data is not None else bytes()
        self.le = le
        self.force_extended = extended

    
    def to_bytes(self) -> bytes:
        """To bytes

        Raises:
            ValueError: Invalid property `data`

        Returns:
            bytes: The instance as bytes
        """
        extended = self.force_extended or len(self.data) > 0x100 or self.le == "max" or self.le > 0x100
        maxExpectedResponseLength = 0
        if self.le == "max":
            maxExpectedResponseLength = 0x10000
        elif self.le > 0:
            maxExpectedResponseLength = self.le

        buffer = bytearray()
        buffer.append(self.cla)
        buffer.append(self.ins)
        buffer.append(self.p1)
        buffer.append(self.p2)
        if len(self.data) > 0:
            if extended:
                buffer.append(0x00)
                buffer.extend(len(self.data).to_bytes(2, "big"))
            else:
                buffer.append(len(self.data))
            buffer.extend(self.data)
        if maxExpectedResponseLength > 0:
            if extended:
                if len(self.data) == 0:
                    buffer.append(0x00)
                if maxExpectedResponseLength == 0x10000:
                    buffer.extend(0x00.to_bytes(2, "big"))
                else:
                    buffer.extend(maxExpectedResponseLength.to_bytes(2, "big"))
            else:
                if maxExpectedResponseLength == 0x100:
                    buffer.append(0x00)
                else:
                    buffer.append(maxExpectedResponseLength)
        return bytes(buffer)

        # buffer = bytearray()
        # buffer.append(self.cla)
        # buffer.append(self.ins)
        # buffer.append(self.p1)
        # buffer.append(self.p2)


#   @JvmOverloads
#   fun serialize(forceExtended: Boolean = false): ByteArray {
#     val extended = forceExtended || data.size > NORMAL_LC_MAX ||
#       maxExpectedResponseLength > NORMAL_LE_MAX

#     val baos = ByteArrayOutputStream()
#     val output = DataOutputStream(baos)
#     output.write(byteArrayOf(commandClass, instruction, parameter1, parameter2))

#     if (data.isNotEmpty()) {
#       if (extended) {
#         output.writeByte(0x00)
#         output.writeShort(data.size)
#       } else {
#         output.writeByte(data.size)
#       }

#       output.write(data)
#     }

#     if (maxExpectedResponseLength > 0) {
#       if (extended) {
#         if (data.isEmpty()) {
#           output.writeByte(0x00)
#         }

#         if (maxExpectedResponseLength == EXTENDED_LE_MAX) {
#           output.writeShort(0x00)
#         } else {
#           output.writeShort(maxExpectedResponseLength)
#         }
#       } else {
#         if (maxExpectedResponseLength == NORMAL_LE_MAX) {
#           output.writeByte(0x00)
#         } else {
#           output.writeByte(maxExpectedResponseLength)
#         }
#       }
#     }

#     return baos.toByteArray()
#   }