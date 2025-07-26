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
import json  # --- 新增导入 ---
import concurrent.futures # --- 新增导入 ---

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

# 推送函数
# def Push(contents):
#     # 推送加
#     headers = {'Content-Type': 'application/json'}
#     json = {"token": plustoken, 'title': '天翼云签到', 'content': contents.replace('\n', '<br>'), "template": "json"}
#     resp = requests.post(f'http://www.pushplus.plus/send', json=json, headers=headers).json()
#     print('push+推送成功' if resp['code'] == 200 else 'push+推送失败')

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

# --- 修改函数：增强健壮性 ---
def safe_json_loads(response, context=""):
    """
    安全地从 requests.Response 对象加载 JSON，处理 BOM。
    """
    try:
        # 首先尝试直接解析，大多数情况都适用
        return response.json()
    except requests.exceptions.JSONDecodeError as e1:
        # 如果失败，检查并处理 BOM
        try:
            text_content = response.text
            # UTF-8 BOM 是 \ufeff
            if text_content.startswith('\ufeff'):
                text_content = text_content[1:]
            return json.loads(text_content)
        except (json.JSONDecodeError, UnicodeError) as e2:
            print(f"[错误] {context} JSON 解析失败:")
            print(f"  初始错误: {e1}")
            print(f"  BOM处理后错误: {e2}")
            print(f"  响应状态码: {response.status_code}")
            print(f"  响应头 Content-Type: {response.headers.get('content-type', 'N/A')}")
            # 打印部分内容用于调试，注意可能包含敏感信息
            preview = response.text[:200] if response.text else "Empty response"
            print(f"  响应内容预览: {repr(preview)}")
            raise # 重新抛出异常，让调用者决定如何处理

def calculate_md5_sign(params):
    return hashlib.md5('&'.join(sorted(params.split('&'))).encode('utf-8')).hexdigest()

# --- 修改函数：处理 BOM 和 URL ---
def get_encrypt_key():
    """
    获取公钥
    :return:
    """
    data = {'appId': 'cloud'}
    # 修正 URL 前后的空格
    url = 'https://open.e.189.cn/api/logbox/config/encryptConf.do'
    res = requests.post(url, data=data)
    res.raise_for_status() # 先检查 HTTP 状态
    # 使用安全的 JSON 解析
    json_data = safe_json_loads(res, "获取加密密钥")
    result = json_data.get('result', 0)
    if result != 0:
        print('get public key error')
        return ''
    data = json_data['data']
    encrypt_key = data['pubKey']
    return encrypt_key

# --- 修改函数：处理重定向和 URL ---
def redirect_url():
    """
    获取 lt 及 reqId
    :return:
    """
    # 修正 URL 前后的空格
    url = 'https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https://cloud.189.cn/web/redirect.html?returnURL=/main.action'
    r = requests.get(url, allow_redirects=True) # 明确允许重定向
    r.raise_for_status()
    
    # 增强健壮性：检查是否有重定向历史
    if not r.history:
        print("[警告] redirect_url: 没有发生重定向，可能已直接登录或页面结构变化。")
        # 如果没有重定向，可能已经在目标页面，或者需要不同的处理方式
        # 这里我们尝试从当前响应中获取 Location (虽然不太可能)
        # 或者直接抛出异常，因为逻辑依赖于重定向
        # 根据知识库信息，正常流程应该有重定向
        # 如果没有，可能需要检查 cookies 或者是已经登录的状态
        # 为了兼容性，我们尝试获取 Location header
        location = r.headers.get('Location')
        if not location:
             # 如果连 Location header 都没有，且无历史，说明可能直接返回了内容（如已登录）
             # 根据知识库信息，这似乎意味着已登录或需要验证
             # 我们尝试从当前 URL 解析（但这通常不对）
             # 最安全的做法是抛出异常或返回空，让后续逻辑处理
             print("[错误] redirect_url: 无重定向历史且无 Location header。响应内容可能表示已登录或需要验证。")
             print(f"       当前 URL: {r.url}")
             # 尝试打印部分内容看是否是登录验证页面 (根据知识库)
             preview = r.text[:500] if r.text else "Empty response"
             print(f"       响应内容预览: {repr(preview)}")
             raise Exception("redirect_url failed: No redirect history and no Location header. Check if already logged in or verification is required.")
        final_url = location
    else:
        # 正常情况：从最后一次重定向获取 Location
        final_url = r.history[-1].headers.get('Location')
        
    if not final_url:
        raise Exception("redirect_url failed: Could not find redirect Location.")

    query = parse_qs(urlparse(final_url).query)
    return query

# --- 修改函数：处理 BOM 和 URL ---
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
        # 修正 Referer URL 前后的空格
        'Referer': 'https://open.e.189.cn/',
        'lt': query['lt'][0],
        'REQID': query['reqId'][0],
    }
    # 修正 URL 前后的空格
    url = 'https://open.e.189.cn/api/logbox/oauth2/appConf.do'
    res = requests.post(url, headers=headers, data=data)
    res.raise_for_status() # 先检查 HTTP 状态
    # 使用安全的 JSON 解析
    json_data = safe_json_loads(res, "获取登录表单配置")
    if json_data['result'] == '0':
        username_encrypt_base64 = rsa_encode(encrypt_key, username)
        password_encrypt_base64 = rsa_encode(encrypt_key, password)
        data = {
            'returnUrl': json_data['data']['returnUrl'],
            'paramId': json_data['data']['paramId'],
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
    :return:
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
    # 修正 URL 前后的空格
    login_url = 'https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do'
    response = requests.post(login_url,
                             headers={
                                 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
                                 # 修正 Referer URL 前后的空格
                                 'Referer': 'https://open.e.189.cn/',
                                 'lt': formData['lt'],
                                 'REQID': formData['REQID']
                             },
                             data=data)
    response.raise_for_status()
    # 使用安全的 JSON 解析
    json_res = safe_json_loads(response, "提交登录")
    if json_res['result'] != 0:
        raise Exception(json_res['msg'])
    response = client.get(json_res['toUrl'])
    response.raise_for_status()
    return response.status_code

def do_login(username, password):
    """
    登录流程：1.获取公钥 -> 2.获取登录参数 -> 3.获取登录地址,跳转到登录页
    """
    encrypt_key = get_encrypt_key()
    login_form_data = get_login_form_data(username, password, encrypt_key)
    login_result = login(login_form_data)
    return encrypt_key, login_form_data, login_result

def do_get(task_url):
    """
    发送 GET 请求
    """
    url_parts = urllib.parse.urlparse(task_url)
    client.headers['Host'] = url_parts.netloc
    response = client.get(task_url)
    response.raise_for_status()
    # 使用安全的 JSON 解析
    json_data = safe_json_loads(response, f"执行任务 {task_url}")
    return json_data

def do_task():
    """
    任务 1.签到 2.天天抽红包 3.自动备份抽红包
    """
    # 修正 URLs 前后的空格
    tasks = [
        f"https://cloud.189.cn/mkt/userSign.action?rand={int(time.time() * 1000)}&clientType=TELEANDROID&version={VERSION}&model={MODEL}",
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN',
    ]

    result = []
    for index, task in enumerate(tasks):
        if index > 1:
            time.sleep(5) # 避免第2,3次抽奖请求过快
        json_data = do_get(task)
        if index == 0:
            # 签到
            if json_data['isSign']:
                result.append('已经签到过了')
            result.append(f"签到获得{json_data['netdiskBonus']}M空间")
        else:
            if json_data.get('errorCode', '') == 'User_Not_Chance':
                result.append(f"第{index}次抽奖失败,次数不足")
            else:
                result.append(f"第{index}次抽奖成功,抽奖获得{json_data.get('prizeName', '')}")
    return result

# --- 新增函数：用于并发执行 ---
# 为了并发且不修改原 do_task 逻辑，每个并发进程需要独立登录
def _run_do_task(username, password):
    """在独立进程中运行的任务，包含重新登录"""
    try:
        # 重新登录以获取独立的 session
        do_login(username, password)
        # 执行任务
        result = do_task()
        return result
    except Exception as e:
        return [f"并发任务执行失败: {e}"]
# -----------------------------

def main(ty_username, ty_password):
    result_list = []
    encrypt_key, login_form_data, login_result = do_login(ty_username, ty_password)
    if login_result == 200:
        result_list.append('天翼网盘登录成功')
    # 执行第一次签到任务
    result = do_task()
    result_list.extend(result)
    
    # --- 新增并发逻辑 ---
    try:
        # 启动 7 个并发进程执行签到任务
        num_processes = 7
        with concurrent.futures.ProcessPoolExecutor(max_workers=num_processes) as executor:
            # 提交任务：每个任务都是重新登录并执行 do_task
            future_to_index = {executor.submit(_run_do_task, ty_username, ty_password): i for i in range(num_processes)}
            
            concurrent_results = []
            for future in concurrent.futures.as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    data = future.result()
                    # 将每个并发任务的结果列表连接成字符串
                    concurrent_results.append(f"[并发{index+1}] {'。'.join(data)}")
                except Exception as exc:
                    concurrent_results.append(f'[并发{index+1}] 产生异常: {exc}')
            
            # 将并发结果添加到最终结果列表
            result_list.extend(concurrent_results)
            
    except Exception as e:
        result_list.append(f"启动并发任务时出错: {e}")
    # ---------------------

    result_string = "。".join(result_list)
    print(result_list)
    return result_string


if __name__ == "__main__":
    if ty_user != None and ty_pwd != None:
        content = main(ty_user, ty_pwd)
        send = MessageSend()
        send.send_all(message_tokens,'天翼盘签到', content)
