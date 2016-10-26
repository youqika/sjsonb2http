#! /usr/bin/env python
# -*- coding:utf-8 -*-


import sys
import json
import base64
import requests


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "no auth"
        sys.exit(1)

    auth = base64.encodestring(sys.argv[1]).replace("\n", "")
    headers_extra = {"Authorization": "Basic {}".format(auth), "content-type": "application/json"}
    d = {"platform":"ios","audience":{"alias":["E04CB2D9BCCFBDC9"]},"notification":{"android":{"extras":{"type":"alarm","value0":"0","time":"2016-10-11 17:52:53"},"builder_id":3,"alert":"警报测试"},"ios":{"sound":"happy","extras":{"type":"alarm","value0":"0","time":"2016-10-11 17:52:53"},"badge":1,"alert":"警报测试"}},"options":{"sendno":123456789,"time_to_live":60,"apns_production":True}}
    r = requests.post(
        "https://api.jpush.cn/v3/push/", headers = headers_extra, data = json.dumps(d)
    )
    print r.content
