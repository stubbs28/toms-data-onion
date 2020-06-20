import base64

def getLayer(data):
    """Returns instructions and payload from onion layer.

    Keyword arguments:
    data -- an array of strings (lines in a text file).
    """

    layer={}
    current=''
    for line in data:
        if line.startswith('==[ Layer'):
            current='instructions'
            continue
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
    p = ''.join(payload.splitlines())
    p = str.encode(p)
    return base64.a85decode(p, adobe=True)

def bytesToString(data):
    return data.decode('utf-8').splitlines(True)

def decode0(payload):
    return getLayer(bytesToString(payloadToBytes(payload)))

def decode1(payload):
    p = bytearray(payloadToBytes(payload))
    for i in range(len(p)):
        b = p[i] ^ 0x55
        p[i] = ((b & 1) << 7) | (b >> 1)
    return getLayer(bytesToString(p))

def decode2(payload):
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

known_string = b'==[ Layer 4/5: Network Traffic ]=='
def decode3(payload):
    p = payloadToBytes(payload)
    k = bytearray()
    for i in range(32):
        k.append(p[i] ^ known_string[i])
    r = bytearray(len(p))
    for i in range(len(p)):
        r[i] = k[i % 32] ^ p[i]
    return getLayer(bytesToString(r))

class ipv4Packet:
    srcaddr = 0x0A01010A
    dstaddr = 0x0A0101C8
    def __init__(self, b):
        self.length = int.from_bytes(b[2:4], byteorder='big', signed=False)
        self.protocol = int.from_bytes(b[8:10], byteorder='big', signed=False) & 0xFF
        self.srcaddr = int.from_bytes(b[12:16], byteorder='big', signed=False)
        self.dstaddr = int.from_bytes(b[16:20], byteorder='big', signed=False)
        s = 0
        for x in range(20)[::2]:
            s += int.from_bytes(b[x:x+2], byteorder='big', signed=False)
        self.checksum = ~((s >> 16) + s) & 0xFFFF
        self.payload = udpPacket(b[20:self.length], self.protocol)

    def isValid(self):
        if self.checksum != 0:
            print('bad checksum: {0}'.format(self.checksum))
            return False
        if self.srcaddr != ipv4Packet.srcaddr:
            print('bad srcaddr: {0}.{1}.{2}.{3}'.format(self.srcaddr >> 24, (self.srcaddr >> 16) & 0xFF, (self.srcaddr >> 8) & 0xFF, self.srcaddr & 0xFF))
        if self.dstaddr != ipv4Packet.dstaddr:
            print('bad srcaddr: {0}.{1}.{2}.{3}'.format(self.dstaddr >> 24, (self.dstaddr >> 16) & 0xFF, (self.dstaddr >> 8) & 0xFF, self.dstaddr & 0xFF))
        return self.payload.isValid()

class udpPacket:
    dstport = 42069
    def __init__(self, b, p):
        self.dstport = int.from_bytes(b[2:4], byteorder='big', signed=False)
        self.length = int.from_bytes(b[4:6], byteorder='big', signed=False)
        s = self.length + p + 0x0A01 + 0x010A + 0x0A01 + 0x01C8
        for x in range(self.length)[::2]:
            s += int.from_bytes(b[x:x+2], byteorder='big', signed=False)
        self.checksum = ~((s >> 16) + s) & 0xFFFF
        self.payload = b[8:self.length]

    def isValid(self):
        if self.checksum != 0:
            print('bad udp checksum: {0}'.format(self.checksum))
            return False
        if self.dstport != udpPacket.dstport:
            print('bad dst port: {0}'.format(self.dstport))
        return True

def decode4(payload):
    p = payloadToBytes(payload)
    i = 0
    c = 0
    r = bytearray()
    while i < len(p):
        print('processing packet {0}'.format(c))
        packet = ipv4Packet(p[i:])
        i += packet.length
        if packet.isValid():
            r.append(packet.payload.payload)
        c += 1
        exit(1)
    return getLayer(bytesToString(r))

def main():
    decoder = {
        0: decode0,
        1: decode1,
        2: decode2,
        3: decode3,
        4: decode4
    }
    with open('onion.txt', 'r') as f:
        data = f.readlines()
    layer = getLayer(data)
    for x in range(5):
        print(layer['instructions'])
        if x in decoder:
            layer = decoder[x](layer['payload'])
            print('==[Layer {0} Decoded]'.format(x).ljust(60, '='))
        else:
            print('==[Decoder {0} not implemented]'.format(x).ljust(60, '='))
            break

if __name__ == '__main__':
    main()
