#!/usr/bin/python3
# -- coding: utf-8 --
# @Time : 2023/5/30 9:23
# 作者：boci
# -------------------------------
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
import queue  # 用于线程间安全地共享结果

VERSION = '9.0.6'
MODEL = 'KB2000'
CLIENT_ID = '538135150693412'
BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
client = requests.Session()
client.headers.update(**{
    'User-Agent': f"Mozilla/5.0 (Linux; U; Android 11; {MODEL} Build/RP1A.201005.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/{VERSION} Android/30 clientId/{CLIENT_ID} clientModel/{MODEL} clientChannelId/qq proVersion/1.0.6",
    'Host': 'cloud.189.cn',
    'Referer': 'https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1',
    'Accept-Encoding': 'gzip, deflate',
})

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
        print('获取公钥失败')
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

def login(formData):
    data = {
        'appKey': 'cloud',
        'version': '2.0',
        'accountType': '01',
        'mailSuffix': '@189.cn',
        'validateCode': '',
        'returnUrl': formData['returnUrl'],
        'paramId': formData['paramId'],
        'captchaToken': '',
        'dynamicCheck': 'FALSE',
        'clientType': '1',
        'cb_SaveName': '0',
        'isOauth2': False,
        'userName': formData['userName'],
        'password': formData['password'],
    }
    response = requests.post('https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do',
                             headers={
                                 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
                                 'Referer': 'https://open.e.189.cn/',
                                 'lt': formData['lt'],
                                 'REQID': formData['REQID']
                             },
                             data=data)
    response.raise_for_status()
    json = response.json()
    if json['result'] != 0:
        raise Exception(json['msg'])
    response = client.get(json['toUrl'])
    response.raise_for_status()
    return response.status_code

def do_get(task_url):
    url_parts = urllib.parse.urlparse(task_url)
    client.headers['Host'] = url_parts.netloc
    response = client.get(task_url)
    response.raise_for_status()
    json_data = response.json()
    return json_data

def do_task(result_queue):
    tasks = [
        f"https://cloud.189.cn/mkt/userSign.action?rand={int(time.time() * 1000)}&clientType=TELEANDROID&version={VERSION}&model={MODEL}",
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN',
    ]
    result = []
    for index, task in enumerate(tasks):
        if index > 1:
            time.sleep(5)
        json_data = do_get(task)
        if index == 0:
            if json_data['isSign']:
                result.append('已经签到过了')
            result.append(f"签到获得{json_data['netdiskBonus']}M空间")
        else:
            if json_data.get('errorCode', '') == 'User_Not_Chance':
                result.append(f"第{index}次抽奖失败,次数不足")
            else:
                result.append(f"第{index}次抽奖成功,抽奖获得{json_data.get('prizeName', '')}")

    total_space = sum([int(x.split('M')[0]) for x in result if '签到获得' in x])
    result.append(f"总空间：{total_space}M")
    
    # 将任务结果推送到队列中
    result_queue.put(result)

def run_threaded_signin(ty_username, ty_password, num_threads=10):
    result_list = []
    encrypt_key, login_form_data, login_result = do_login(ty_username, ty_password)
    if login_result == 200:
        result_list.append('天翼网盘登录成功')
    
    threads = []
    result_queue = queue.Queue()  # 创建线程安全的队列，用于存放每个线程的结果
    
    for _ in range(num_threads):
        thread = threading.Thread(target=do_task, args=(result_queue,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    # 从队列中获取每个线程的结果并汇总
    while not result_queue.empty():
        result_list.extend(result_queue.get())
    
    result_string = "。".join(result_list)
    print(result_list)
    return result_string

def main(ty_username, ty_password):
    return run_threaded_signin(ty_username, ty_password)

if __name__ == "__main__":
    if ty_user != None and ty_pwd != None:
        content = main(ty_user, ty_pwd)
        send = MessageSend()
        send.send_all(message_tokens, '天翼云签到', content)
