#! /usr/bin/env python
# -*- coding:utf-8 -*-


'''
sjson协议格式
[magic num(4) | 版本(4) | 内容起始偏移(4) | 内容长度(4) | 内容校验码(4) | 扩展区 | 内容]
'''


import os
import sys
import time
import struct
import errno
import socket
import json
import logging
import urllib, httplib
import crash_on_ipy

from functools import partial
from tornado.ioloop import IOLoop
from tornado.process import fork_processes
from tornado.netutil import bind_sockets


def string2addr(addr_name):
    return ()


def addr2string(addr_tuple):
    ip, port = addr_tuple
    return ip + ":" + str(port)


class Transformer(object):
    def __init__(self, io_loop, sock_lsn, pool_size):
        self._io_loop = io_loop
        self._sock_lsn = sock_lsn
        self._cli_conn = {} # 连接集
        self._MAX_CONNECTIONS = 1
        self._PROTO_MAGIC_NO = 0xE78F8A9D
        self._LEN_HEADER = 20
        self._LEN_MIN_LOADING = 2
        self._LEN_MIN_PACK = self._LEN_HEADER + self._LEN_MIN_LOADING # 最小包长度(包头+最小json对象)


    '''
    sjsonb协议打包函数
    '''
    def _pack_sjsonb(cargo):
        str_cargo = json.dumps(cargo, separators=(",", ":"))
        package = struct.pack("!5I{}s".format(len(str_cargo)),
                              self._PROTO_MAGIC_NO, 0, self._LEN_HEADER,
                              len(str_cargo), 0, str_cargo)
        return package


    def _release_conn(self, conn):
        skt = conn["socket"]

        del self._cli_conn[skt] # 从连接集中剔除
        self._io_loop.remove_handler(skt.fileno()) # 停止监视
        skt.close()


    ''' 请求回调 '''
    def handle_req(self, conn, fd, events):
        skt = conn["socket"]

        try:
            rbuf = skt.recv(4096)
        except socket.error as e:
            self._release_conn(conn)
            return

        if len(rbuf) == 0:
            # client closed
            self._release_conn(conn)
            return

        conn["rbuf"] += rbuf

        # 协议检查
        if len(conn["rbuf"]) < self._LEN_MIN_PACK:
            # 内容不足以解析
            logging.debug("cant parse header, length not enough")
            return

        idx_magic = conn["rbuf"].find(struct.pack("!I", self._PROTO_MAGIC_NO))
        if -1 == idx_magic:
            # 无法找到包头
            logging.debug("magic number not found")
            self._release_conn(conn)
            return

        conn["rbuf"] = conn["rbuf"][idx_magic :] # 丢弃无效数据

        _, version, start_ofst, length, checksum = struct.unpack(
            "!5I", conn["rbuf"][0 : self._LEN_HEADER]
        )
        if (start_ofst < self._LEN_HEADER or length < 2 or length > 4096):
            logging.debug("invalid package")
            self._release_conn(conn)
            return

        len_pending = len(conn["rbuf"][start_ofst :])
        if (len_pending < length):
            # 内容不足以解析
            logging.debug("cant parse body, length not enough")
            return

        context_data = conn["rbuf"][start_ofst : start_ofst+length]
        conn["rbuf"] = conn["rbuf"][start_ofst+length :] # 丢弃已解析的数据

        try:
            logging.debug("request: {}".format(context_data))
            cli_obj = json.loads(context_data)
        except ValueError as e:
            self._release_conn(conn)
            return

        '''===== 协议解析完成 ====='''

        if "method" not in cli_obj:
            self._release_conn(conn)
            return

        if "url" not in cli_obj:
            self._release_conn(conn)
            return

        if "jpush_msg" not in cli_obj:
            self._release_conn(conn)
            return

        http_conn = httplib.HTTPConnection(cli_obj["url"])
        http_conn.request("GET", "/")
        skt.sendall(http_conn.getresponse().read())
        http_conn.close()


    ''' 连接回调 '''
    def handle_connection(self, fd, events):
        if len(self._cli_conn) >= self._MAX_CONNECTIONS:
            # 过载保护
            while True:
                try:
                    conn_skt, addr = self._sock_lsn.accept()
                    conn_skt.close()
                except socket.error as e:
                    if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
                        logging.error("accept failed: {}".format(e));
                    break
            return

        try:
            conn_skt, addr = self._sock_lsn.accept()
        except socket.error as e:
            if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
                logging.error("accept failed: {}".format(e));
            return

        conn_skt.setblocking(0)
        connection = { # 新连接
            "socket":conn_skt, "address":addr2string(addr), "rbuf":""
        }
        self._cli_conn[conn_skt] = connection
        self._io_loop.add_handler(conn_skt.fileno(),
                                  partial(self.handle_req, connection),
                                  self._io_loop.READ | self._io_loop.ERROR)


if "__main__" == __name__:
    logging.basicConfig(
        level = logging.DEBUG,
        format = ("%(asctime)s %(filename)s"
            + "[line:%(lineno)d] %(levelname)s %(message)s"
        ),
        datefmt = "%Y.%m.%d %H:%M:%S",
        filename = "log/my_store.log",
        filemode = "a"
    )

    sock_lsn = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock_lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_lsn.setblocking(0)
    sock_lsn.bind(("", 11211))
    sock_lsn.listen(65535)

    while True:
        try:
            # 该函数在父进程要么exit，要么抛异常，不会返回
            task_id = fork_processes(num_processes = 1, max_restarts = 1)
        except RuntimeError as e:
            logging.error("fork failed: {}".format(e))
            time.sleep(60) # 重启间隔
        else:
            # 子进程
            break

    io_loop = IOLoop.current()
    server = Transformer(io_loop, sock_lsn, 1)
    io_loop.add_handler(sock_lsn.fileno(),
                        server.handle_connection,
                        io_loop.READ | io_loop.ERROR)
    io_loop.start()
