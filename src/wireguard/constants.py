import struct

from enum import IntEnum

from .functions import wg_hash


# yapf: disable
class MessageTypes(IntEnum):
	MSG_HANDSHAKE_REQ = 0x01
	MSG_HANDSHAKE_RES = 0x02
	MSG_COOKIE_REPLY  = 0x03
	MSG_TRANSPORT     = 0x04


TEMPLATE_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
TEMPLATE_IDENTIFIER   = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
TEMPLATE_LABEL_MAC    = b"mac1----"
TEMPLATE_LABEL_COOKIE = b"cookie--"
TEMPLATE_EMPTY_MAC    = b'\x00' * 16
TEMPLATE_EMPTY_KEY    = b'\x00' * 32

STATE_REKEY_AFTER_MSGS   = 2 ** 60
STATE_REJECT_AFTER_MSGS  = 2 ** 64 - 2 ** 13 - 1
STATE_REKEY_AFTER_TIME   = 120
STATE_REJECT_AFTER_TIME  = 180
STATE_REKEY_ATTEMPT_TIME = 90
STATE_REKEY_TIMEOUT      = 5
STATE_KEEPALIVE_TIMEOUT  = 10
STATE_COOKIE_LIFETIME    = 120

# u8 Type, u8[3] Reserved
STRUCT_HEADER        = "<B3x"
# u8[16] MAC1, u8[16] MAC2
STRUCT_MACS          = "<16s16s"
# u32 Sender, u8[32] Ephemeral, u8[48] AEAD(Static), u8[28] AEAD(Timestamp)
STRUCT_HANDSHAKE_REQ = "<I32s48s28s" # Append MACs
# u32 Sender, u32 Receiver, u8[32] Ephemeral, u8[16] AEAD(Empty)
STRUCT_HANDSHAKE_RES = "<II32s16s" # Append MACs
# u32 Receiver, u8[24] Nonce, u8[32] AEAD(Cookie)
STRUCT_COOKIE_REPLY  = "<I24s32s"
# u32 Receiver, u64 Counter
STRUCT_TRANSPORT     = "<IQ" # Append data

LEN_HEADER              = struct.calcsize(STRUCT_HEADER)
LEN_MACS                = struct.calcsize(STRUCT_MACS)
LEN_HANDSHAKE_REQ       = struct.calcsize(STRUCT_HANDSHAKE_REQ)
LEN_HANDSHAKE_REQ_TOTAL = LEN_HEADER + LEN_HANDSHAKE_REQ + LEN_MACS
LEN_HANDSHAKE_RES       = struct.calcsize(STRUCT_HANDSHAKE_RES)
LEN_COOKIE_REPLY        = struct.calcsize(STRUCT_COOKIE_REPLY)
LEN_TRANSPORT           = struct.calcsize(STRUCT_TRANSPORT)

# Pre-compute header bytes
HDR_HANDSHAKE_REQ = struct.pack(STRUCT_HEADER, MessageTypes.MSG_HANDSHAKE_REQ)
HDR_HANDSHAKE_RES = struct.pack(STRUCT_HEADER, MessageTypes.MSG_HANDSHAKE_RES)
HDR_COOKIE_REPLY  = struct.pack(STRUCT_HEADER, MessageTypes.MSG_COOKIE_REPLY)
HDR_TRANSPORT     = struct.pack(STRUCT_HEADER, MessageTypes.MSG_TRANSPORT)

INITIAL_CHAINING_KEY   = wg_hash(TEMPLATE_CONSTRUCTION)
INITIAL_HANDSHAKE_HASH = wg_hash(INITIAL_CHAINING_KEY + TEMPLATE_IDENTIFIER)
# yapf: enable
