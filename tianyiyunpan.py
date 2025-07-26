#!/usr/bin/python3
# -- coding: utf-8 --
# @Time : 2023/5/30 9:23
# 作者：boci
# -------------------------------
# cron "30 4 * * *" script-path=xxx.py,tag=匹配cron用
# const $ = new Env('天翼云盘签到');
from message_send import MessageSend
from config import message_tokens, ty_pwd, ty_user
import time
import urllib
import base64
import hashlib
from urllib.parse import urlparse, parse_qs
import rsa
import requests
import os
import threading
import random
import queue

VERSION = '9.0.6'
MODEL = 'KB2000'
CLIENT_ID = '538135150693412'
BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def int2char(a):
    return BI_RM[a]

def b64tohex(a):
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = B64MAP.index(list(a)[i])
            if 0 == e:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d

def rsa_encode(encrypt_key, string):
    rsa_key = f"-----BEGIN PUBLIC KEY-----\n{encrypt_key}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
    return result

def calculate_md5_sign(params):
    return hashlib.md5('&'.join(sorted(params.split('&'))).encode('utf-8')).hexdigest()

def get_encrypt_key():
    data = {'appId': 'cloud'}
    url = 'https://open.e.189.cn/api/logbox/config/encryptConf.do'
    res = requests.post(url, data=data).json()
    result = res.get('result', 0)
    if result != 0:
        print('get public key error')
        return ''
    data = res['data']
    encrypt_key = data['pubKey']
    return encrypt_key

def redirect_url():
    url = 'https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https://cloud.189.cn/web/redirect.html?returnURL=/main.action'
    r = requests.get(url)
    r.raise_for_status()
    query = parse_qs(urlparse(r.history[-1].headers['Location']).query)
    return query

def get_login_form_data(username, password, encrypt_key):
    query = redirect_url()
    data = {
        'version': '2.0',
        'appKey': 'cloud'
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
        'Referer': 'https://open.e.189.cn/',
        'lt': query['lt'][0],
        'REQID': query['reqId'][0],
    }
    url = 'https://open.e.189.cn/api/logbox/oauth2/appConf.do'
    res = requests.post(url, headers=headers, data=data).json()
    if res['result'] == '0':
        username_encrypt_base64 = rsa_encode(encrypt_key, username)
        password_encrypt_base64 = rsa_encode(encrypt_key, password)
        data = {
            'returnUrl': res['data']['returnUrl'],
            'paramId': res['data']['paramId'],
            'lt': query['lt'][0],
            'REQID': query['reqId'][0],
            "userName": f"{{NRP}}{username_encrypt_base64}",
            "password": f"{{NRP}}{password_encrypt_base64}",
        }
        return data

def sign_in(username, password, result_queue):
    client = requests.Session()
    client.headers.update(**{
        'User-Agent': f"Mozilla/5.0 (Linux; U; Android 11; {MODEL} Build/RP1A.201005.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/{VERSION} Android/30 clientId/{CLIENT_ID} clientModel/{MODEL} clientChannelId/qq proVersion/1.0.6",
        'Host': 'cloud.189.cn',
        'Referer': 'https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1',
        'Accept-Encoding': 'gzip, deflate',
    })
    
    # Add random delay to simulate human behavior
    time.sleep(random.uniform(1, 5))
    
    result = []
    try:
        # Get encryption key
        encrypt_key = get_encrypt_key()
        if not encrypt_key:
            result.append('获取公钥失败')
            result_queue.put(result)
            return
        
        # Get login form data
        login_form_data = get_login_form_data(username, password, encrypt_key)
        if not login_form_data:
            result.append('获取登录参数失败')
            result_queue.put(result)
            return
        
        # Perform login
        data = {
            'appKey': 'cloud',
            'version': '2.0',
            'accountType': '01',
            'mailSuffix': '@189.cn',
            'validateCode': '',
            'returnUrl': login_form_data['returnUrl'],
            'paramId': login_form_data['paramId'],
            'captchaToken': '',
            'dynamicCheck': 'FALSE',
            'clientType': '1',
            'cb_SaveName': '0',
            'isOauth2': False,
            'userName': login_form_data['userName'],
            'password': login_form_data['password'],
        }
        response = requests.post('https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do',
                                 headers={
                                     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
                                     'Referer': 'https://open.e.189.cn/',
                                     'lt': login_form_data['lt'],
                                     'REQID': login_form_data['REQID']
                                 },
                                 data=data)
        response.raise_for_status()
        json_data = response.json()
        if json_data['result'] != 0:
            result.append(f'登录失败: {json_data["msg"]}')
            result_queue.put(result)
            return
        response = client.get(json_data['toUrl'])
        response.raise_for_status()
        result.append('天翼网盘登录成功')
        
        # Perform sign-in tasks
        tasks = [
            f"https://cloud.189.cn/mkt/userSign.action?rand={int(time.time() * 1000)}&clientType=TELEANDROID&version={VERSION}&model={MODEL}",
            'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN',
            'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN',
            'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN',
        ]
        
        for index, task in enumerate(tasks):
            if index > 0:
                time.sleep(random.uniform(1, 3))  # Delay between prize draws
            url_parts = urllib.parse.urlparse(task)
            client.headers['Host'] = url_parts.netloc
            response = client.get(task)
            response.raise_for_status()
            json_data = response.json()
            if index == 0:
                if json_data['isSign']:
                    result.append('已经签到过了')
                result.append(f"签到获得{json_data['netdiskBonus']}M空间")
            else:
                if json_data.get('errorCode', '') == 'User_Not_Chance':
                    result.append(f"第{index}次抽奖失败,次数不足")
                else:
                    result.append(f"第{index}次抽奖成功,抽奖获得{json_data.get('prizeName', '')}")
    except Exception as e:
        result.append(f'签到过程中发生错误: {e}')
    
    result_queue.put(result)

def main(ty_username, ty_password):
    result_queue = queue.Queue()
    threads = []
    
    # Create and start 7 threads
    for _ in range(7):
        t = threading.Thread(target=sign_in, args=(ty_username, ty_password, result_queue))
        threads.append(t)
        t.start()
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    # Collect results from all threads
    all_results = []
    while not result_queue.empty():
        all_results.append(result_queue.get())
    
    # Format and send the results
    content = "\n".join(["。".join(res) for res in all_results])
    print(content)
    return content

if __name__ == "__main__":
    if ty_user is not None and ty_pwd is not None:
        content = main(ty_user, ty_pwd)
        send = MessageSend()
        send.send_all(message_tokens, '天翼盘签到', content)
