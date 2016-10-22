#! /usr/bin/python


import sys
import json
import struct
import socket


def pack_sjsonb(cargo):
    str_cargo = json.dumps(cargo, separators=(",", ":"))
    package = struct.pack(
        "!5I{}s".format(len(str_cargo)), 0xe78f8a9d, 0, 20, len(str_cargo), 0, str_cargo
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

    cli.send(pack_sjsonb({"method":"get","url":"https://www.baidu.com/","jpush_msg":"asf"}))
    buf = cli.recv(4096)
    print buf
