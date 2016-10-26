#! /usr/bin/env python
# -*- coding:utf-8 -*-


import sys
import json
import struct
import socket


def pack_sjsonb(cargo):
    str_cargo = json.dumps(cargo, separators=(",", ":"))
    package = struct.pack(
        "!5I{}s".format(len(str_cargo)), 0x9d8a8fe7, 0, 20, len(str_cargo), 0, str_cargo
    )
    return package


def unpack_sjsonb(package):
    magic_no, _, ent_offset, ent_sz, _ = struct.unpack("!5I", package[0:20])
    str_cargo = package[ent_offset : ent_offset + ent_sz]
    cargo = json.loads(str_cargo)
    return cargo


if __name__ == "__main__":
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cli.connect(("127.0.0.1", 11211))
    except socket.error as e:
        print e
        sys.exit(1)

    d = {"platform":"ios","audience":{"alias":["E04CB2D9BCCFBDC9"]},"notification":{"android":{"extras":{"type":"alarm","value0":"0","time":"2016-10-11 17:52:53"},"builder_id":3,"alert":"警报测试"},"ios":{"sound":"happy","extras":{"type":"alarm","value0":"0","time":"2016-10-11 17:52:53"},"badge":1,"alert":"警报测试"}},"options":{"sendno":123456789,"time_to_live":60,"apns_production":True}}
    cli.send(pack_sjsonb({"method":"post","url":"https://api.jpush.cn/v3/push/","data":json.dumps(d)}))
    buf = cli.recv(4096)
    print buf
