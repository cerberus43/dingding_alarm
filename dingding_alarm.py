#! /usr/bin/python
# -*- coding:utf-8 -*-
# author: cerberus43

import time
import hmac
import hashlib
import base64
import urllib
import requests
import json
import sys
import logging
from dingding_var import init_url, secret_key


def encrypt_url(url, secret):
    timestamp = long(round(time.time() * 1000))
    secret_enc = bytes(secret).encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = bytes(string_to_sign).encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.quote_plus(base64.b64encode(hmac_code))
    post_url = url + '&timestamp=' + str(timestamp) + '&sign=' + sign
    return post_url


def post_msg(post_url, msg, phone_num_list):
    headers = {'Content-Type': 'application/json'}
    if not phone_num_list:
        post_data = {
                        "msgtype": "text",
                        "text": {
                            "content": msg
                        },
                    }
    else:
        post_data = {
                        "msgtype": "text",
                        "text": {
                            "content": msg
                        },
                        "at": {
                            "atMobiles": phone_num_list,
                            "isAtAll": "false"
                        }
                    }
    post_json = json.dumps(post_data)
    r = requests.post(post_url, headers=headers, data=post_json)
    return r.text

def input_log(phone, msg, post_result):
    logging.basicConfig(filename="dingding_alarm.log", filemode="w", format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)
    logging.info('PHONE: %s | Message: %s | RESULT: %s' %(phone, msg.replace("\n",""), post_result))
    

if __name__ == '__main__':
    alarm_phone_num = sys.argv[1]
    alarm_msg = sys.argv[3]

    alarm_phone_list = alarm_phone_num.split(",")
    post_url = encrypt_url(init_url, secret_key)
    request_result = post_msg(post_url, alarm_msg, alarm_phone_list)
    input_log(alarm_phone_num, alarm_msg, request_result)
