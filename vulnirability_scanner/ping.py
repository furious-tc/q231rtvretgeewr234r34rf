from scapy.all import sr1
from scapy.layers.inet import IP, ICMP


def fast_ping(target):
    try:
        packet = IP(dst=target) / ICMP()
        reply = sr1(packet, timeout=0.25, verbose=False)
        if reply:
            return True
        else:
            return False
    except Exception as e:
        return False


if __name__ == "__main__":
    target = "81.19.137.64"
    fast_ping(target)
