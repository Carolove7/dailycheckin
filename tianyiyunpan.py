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
# --- 新增导入 ---
import concurrent.futures
# ----------------

VERSION = '9.0.6'
MODEL = 'KB2000'
CLIENT_ID = '538135150693412'
BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# --- 移除了全局 client 对象 ---
# client = requests.Session()
# client.headers.update(**{
#     'User-Agent': f"Mozilla/5.0 (Linux; U; Android 11; {MODEL} Build/RP1A.201005.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/{VERSION} Android/30 clientId/{CLIENT_ID} clientModel/{MODEL} clientChannelId/qq proVersion/1.0.6",
#     'Host': 'cloud.189.cn',
#     'Referer': 'https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1',
#     'Accept-Encoding': 'gzip, deflate',
# })

# --- 保留原有辅助函数不变 ---
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
    """
    获取公钥
    :return:
    """
    data = {'appId': 'cloud'}
    # 修复 URL 前后的空格
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
    """
    获取 lt 及 reqId
    :return:
    """
    url = 'https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https://cloud.189.cn/web/redirect.html?returnURL=/main.action'
    r = requests.get(url)
    r.raise_for_status()
    query = parse_qs(urlparse(r.history[-1].headers['Location']).query)
    return query

def get_login_form_data(username, password, encrypt_key):
    """
    获取登录参数
    :param username:
    :param password:
    :param encrypt_key:
    :return:
    """
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
    # 修复 URL 前后的空格
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
    """
    获取登录地址,跳转到登录页
    :param formData:
    :return: 返回登录后的 session cookies
    """
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
    # 修复 URL 前后的空格
    login_url = 'https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do'
    response = requests.post(login_url,
                             headers={
                                 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
                                 'Referer': 'https://open.e.189.cn/',
                                 'lt': formData['lt'],
                                 'REQID': formData['REQID']
                             },
                             data=data)
    response.raise_for_status()
    json_res = response.json()
    if json_res['result'] != 0:
        raise Exception(json_res['msg'])

    # 创建一个新的 session 来完成最终的登录跳转
    login_session = requests.Session()
    login_session.headers.update(**{
        'User-Agent': f"Mozilla/5.0 (Linux; U; Android 11; {MODEL} Build/RP1A.201005.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/{VERSION} Android/30 clientId/{CLIENT_ID} clientModel/{MODEL} clientChannelId/qq proVersion/1.0.6",
        'Referer': 'https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1',
        'Accept-Encoding': 'gzip, deflate',
    })
    # 使用登录提交返回的 URL 完成登录，并获取 cookies
    final_response = login_session.get(json_res['toUrl'])
    final_response.raise_for_status()

    # 返回 session 的 cookies 和 headers 用于后续请求
    return login_session.cookies.get_dict(), dict(login_session.headers)

# --- 新增或修改的函数 ---
def perform_login(username, password):
    """
    执行登录流程并返回 cookies 和 headers
    """
    encrypt_key = get_encrypt_key()
    login_form_data = get_login_form_data(username, password, encrypt_key)
    cookies, headers = login(login_form_data)
    return cookies, headers

def do_get_with_session(task_url, cookies, headers):
    """
    使用给定的 cookies 和 headers 发送 GET 请求
    """
    # 创建一个临时 session 来使用传入的 cookies 和 headers
    temp_session = requests.Session()
    temp_session.cookies.update(cookies)
    temp_session.headers.update(headers)

    url_parts = urllib.parse.urlparse(task_url)
    # 更新 Host header
    temp_session.headers['Host'] = url_parts.netloc
    response = temp_session.get(task_url)
    response.raise_for_status()
    json_data = response.json()
    return json_data

def do_task(cookies, headers): # 修改：接受 cookies 和 headers
    """
    任务 1.签到 2.天天抽红包 3.自动备份抽红包
    """
    # 更新 User-Agent 以匹配移动请求
    task_headers = headers.copy()
    task_headers['User-Agent'] = f"Mozilla/5.0 (Linux; U; Android 11; {MODEL} Build/RP1A.201005.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/{VERSION} Android/30 clientId/{CLIENT_ID} clientModel/{MODEL} clientChannelId/qq proVersion/1.0.6"
    task_headers['Referer'] = 'https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1'

    tasks = [
        f"https://cloud.189.cn/mkt/userSign.action?rand={int(time.time() * 1000)}&clientType=TELEANDROID&version={VERSION}&model={MODEL}",
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN',
    ]

    result = []
    for index, task in enumerate(tasks):
        if index > 0: # 从第二次任务开始 sleep
            time.sleep(5) # 避免第2,3次抽奖请求过快
        try:
            json_data = do_get_with_session(task, cookies, task_headers) # 使用传入的 cookies 和 headers
            if index == 0:
                # 签到
                if json_data.get('isSign', False): # 使用 .get() 更安全
                    result.append('[签到] 已经签到过了')
                else:
                    result.append(f"[签到] 获得 {json_data.get('netdiskBonus', 'N/A')}M 空间")
            else:
                # 抽奖
                if json_data.get('errorCode', '') == 'User_Not_Chance':
                    result.append(f"[抽奖{index}] 次数不足")
                else:
                    prize = json_data.get('prizeName', '未知奖品')
                    result.append(f"[抽奖{index}] 成功, 获得 {prize}")
        except Exception as e:
            result.append(f"[任务{index+1}] 执行出错: {e}")

    return "。".join(result) # 每个进程返回自己的结果字符串

def main(ty_username, ty_password):
    result_list = []
    try:
        # 1. 执行一次登录，获取 cookies 和 headers
        cookies, headers = perform_login(ty_username, ty_password)
        result_list.append('天翼网盘登录成功')

        # 2. 使用 ProcessPoolExecutor 创建并发任务
        max_workers = 7
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            # 提交 7 个 do_task 任务
            future_to_task = {executor.submit(do_task, cookies, headers): i for i in range(max_workers)}
            
            # 收集结果
            process_results = []
            for future in concurrent.futures.as_completed(future_to_task):
                task_id = future_to_task[future]
                try:
                    data = future.result()
                    process_results.append(f"[进程{task_id+1}] {data}")
                except Exception as exc:
                    process_results.append(f'[进程{task_id+1}] 产生异常: {exc}')

        result_list.extend(process_results)
        
    except Exception as e:
        result_list.append(f"登录或执行任务时发生错误: {e}")

    result_string = " | ".join(result_list) # 使用 | 分隔不同部分
    print(result_list) # 打印详细列表
    return result_string

# --- 主执行部分 ---
if __name__ == "__main__":
    if ty_user is not None and ty_pwd is not None:
        content = main(ty_user, ty_pwd)
        send = MessageSend()
        send.send_all(message_tokens, '天翼盘签到', content)
    else:
        print("错误：未配置天翼云盘的用户名或密码")
