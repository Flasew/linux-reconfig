import socket
import struct
import sys

SRC_IP = "128.30.92.246"
DST_IP = "128.30.92.246"

def checksum(data):
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def main(args):
    if len(args) not in (5, 4):
        print("Invalid number of arguments", file=sys.stderr)
        sys.exit(1)

    src_port = int(args[1])
    dst_port = int(args[2]) if len(args) == 5 else 0
    dst_id = int(args[3 if len(args) == 5 else 2])
    code = int(args[4 if len(args) == 5 else 3])

    # create a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # create an ICMP network update header
    snd_buf = bytearray(20 + 8)
    iph = struct.pack('!BBHHHBBH4s4s',
                      4 << 4 | 5, 0, 28, 0, 0, 64, socket.IPPROTO_ICMP, 0,
                      socket.inet_aton(SRC_IP), socket.inet_aton(DST_IP))
    snd_buf[:20] = iph
    icmph = struct.pack('!BBHHHBB', 9, code, 0, dst_id, 0, src_port, dst_port)
    snd_buf[20:] = icmph

    iph_checksum = checksum(snd_buf[:20])
    icmph_checksum = checksum(snd_buf[20:])
    snd_buf[10:12] = struct.pack('H', iph_checksum)
    snd_buf[22:24] = struct.pack('H', icmph_checksum)

    # send it
    dst = (DST_IP, 0)
    sock.sendto(snd_buf, dst)

    print("Sent icmp succeed", file=sys.stderr)
    sock.close()

if __name__ == "__main__":
    main(sys.argv)
