import base64
import socket
import struct
from aes_keywrap import aes_unwrap_key
from Crypto.Cipher import AES

def decode0(payload):
    """Returns the decoded payload for Layer 0/5."""

    return getLayer(bytesToString(payloadToBytes(payload)))

def decode1(payload):
    """Returns the decoded payload for Layer 1/5."""

    p = bytearray(payloadToBytes(payload))
    for i in range(len(p)):
        b = p[i] ^ 0x55
        p[i] = ((b & 1) << 7) | (b >> 1)
    return getLayer(bytesToString(p))

def decode2(payload):
    """Returns the decoded payload for Layer 2/5."""

    p = payloadToBytes(payload)
    r = bytearray()
    cur = 0
    for b in p:
        # check byte parity
        parity = b & 1
        total = 0
        for j in range(1, 8):
            total += (b >> j) & 1
        # discard invalid byte
        if (total % 2 == 0) != (parity == 0):
            continue
        # remove parity bit and pack bytes
        b ^= parity
        # pack upper bits into parity hole in prev byte
        if cur > 0:
            r[len(r) - 1] |= b >> (8 - cur)
        # put lower bits into new byte
        if cur == 0 or cur < 7:
            r.append((b << cur) & 0xFF)
            cur += 1
        else:
            cur = 0
    return getLayer(bytesToString(r))

def decode3(payload):
    """Returns the decoded payload for Layer 3/5."""

    # Based on previous layers, I could reasonably assume that the payload
    # started with '==[ Layer 4/5: ', this gave me the first half of the key
    # from there I was able to work out the rest of the key by guessing what
    # partially formed words ought to be.
    known = b'==[ Layer 4/5: Network Traffic ]=='
    p = payloadToBytes(payload)
    k = bytearray()
    for i in range(32):
        k.append(p[i] ^ known[i])
    r = bytearray(len(p))
    for i in range(len(p)):
        r[i] = k[i % 32] ^ p[i]
    return getLayer(bytesToString(r))

def decode4(payload):
    """Returns the decoded payload for Layer 4/5."""

    p = payloadToBytes(payload)
    r = bytearray()
    i = 0
    c = 0
    while i < len(p):
        packet = ipv4Packet(p[i:], c)
        i += packet.length
        if packet.isValid():
            r += packet.payload.payload
        c += 1
    return getLayer(bytesToString(r))

class ipv4Packet:
    srcaddr = 0x0A01010A
    dstaddr = 0x0A0101C8
    def __init__(self, b, i):
        self.id = i
        self.length = int.from_bytes(b[2:4], byteorder='big', signed=False)
        self.protocol = int.from_bytes(b[8:10], byteorder='big', signed=False) & 0xFF
        self.srcaddr = int.from_bytes(b[12:16], byteorder='big', signed=False)
        self.dstaddr = int.from_bytes(b[16:20], byteorder='big', signed=False)
        s = 0
        for x in range(20)[::2]:
            s += int.from_bytes(b[x:x+2], byteorder='big', signed=False)
        self.checksum = ~((s >> 16) + s) & 0xFFFF
        self.payload = udpPacket(b[20:self.length], self.protocol, self.id)

    def isValid(self):
        if self.checksum != 0:
            #print('{0}: bad checksum: {1}'.format(self.id, self.checksum))
            return False
        if self.srcaddr != ipv4Packet.srcaddr:
            #print('{0}: bad srcaddr: {1}'.format(self.id, socket.inet_ntoa(struct.pack("!I", self.srcaddr))))
            return False
        if self.dstaddr != ipv4Packet.dstaddr:
            #print('{0}: bad dstaddr: {1}'.format(self.id, socket.inet_ntoa(struct.pack("!I", self.dstaddr))))
            return False
        return self.payload.isValid()

class udpPacket:
    dstport = 42069
    def __init__(self, b, p, i):
        self.id = i
        self.dstport = int.from_bytes(b[2:4], byteorder='big', signed=False)
        self.length = int.from_bytes(b[4:6], byteorder='big', signed=False)
        s = self.length + p + 0x0A01 + 0x010A + 0x0A01 + 0x01C8
        padded = bytearray(b)
        padded.append(0)
        for x in range(self.length)[::2]:
            s += int.from_bytes(padded[x:x+2], byteorder='big', signed=False)
        self.checksum = ~((s >> 16) + s) & 0xFFFF
        self.payload = b[8:self.length]

    def isValid(self):
        if self.checksum != 0:
            #print('{0}: bad udp checksum: {1}'.format(self.id, self.checksum))
            return False
        if self.dstport != udpPacket.dstport:
            #print('{0}: bad dst port: {1}'.format(self.id, self.dstport))
            return False
        return True


def decode5(payload):
    """Returns the decoded payload for Layer 5/5."""

    p = payloadToBytes(payload)
    partitions = [32, 8, 40, 16]
    sections = []
    for x in partitions:
        sections.append(p[:x])
        p = p[x:]
    # decode the key
    unwrapped = aes_unwrap_key( sections[0], sections[2], int.from_bytes(sections[1], byteorder='big', signed=False))
    cipher = AES.new(unwrapped, AES.MODE_CBC, sections[3])
    print(cipher.decrypt(p).decode('utf-8'))

def getLayer(data):
    """Returns instructions and payload from onion layer."""

    layer={}
    current=''
    for line in data:
        if line.startswith('==[ Layer'):
            current='instructions'
        elif line.startswith('==[ Payload'):
            current='payload'
            continue
        elif current == '':
            continue
        if current not in layer:
            layer[current] = ''
        layer[current] += line
    return layer

def payloadToBytes(payload):
    """Returns a byte array from a payload string."""

    p = ''.join(payload.splitlines())
    p = str.encode(p)
    return base64.a85decode(p, adobe=True)

def bytesToString(data):
    """Returns a string from a byte array."""

    return data.decode('utf-8').splitlines(True)

def main():
    decoders = [
        decode0,
        decode1,
        decode2,
        decode3,
        decode4,
        decode5
    ]
    with open('onion.txt', 'r') as f:
        data = f.readlines()
    layer = getLayer(data)
    for i, d in enumerate(decoders):
        print(layer['instructions'])
        layer = d(layer['payload'])

if __name__ == '__main__':
    main()
