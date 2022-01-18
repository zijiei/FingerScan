# -*- coding: utf-8 -*-
import codecs
import json
import random
import datetime
import re
from socket import inet_aton
from struct import unpack
import mmh3
import hashlib
import select
import socket
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from config.log import logger
from utils import cert_helper
from utils.Wappalyzer import Wappalyzer, WebPage
from config.user_agent import USER_AGENTS
import requests.packages.urllib3.util.ssl_
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 解决ssl 报错，解决sslv3 问题
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'
request_timeout = 10

not_list = ['!body_contains', '!title_contains', '!protocol_contains', '!banner_contains', '!header_contains',
            '!server_contains', '!cert_contains']

vuln_list = [
    '%s/?id=<script>alert("XSS");</script>',
    "%s/?id=1 UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '",
    # '%s/index?path=../../../../etc/passwd',
    # '%s/index?cmd=/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com',
    # '%s/index?xxe=<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'
]

# 检查url合法性
def check_url(url):
    hostname = urlparse(url).hostname

    def ip2long(ip_addr):
        return unpack("!L", inet_aton(ip_addr))[0]

    def is_inner_ipaddress(ip):
        ip = ip2long(ip)
        return ip2long('127.0.0.0') >> 24 == ip >> 24 \
               or ip2long('10.0.0.0') >> 24 == ip >> 24 \
               or ip2long('172.16.0.0') >> 20 == ip >> 20 \
               or ip2long('192.168.0.0') >> 16 == ip >> 16 \
               or ip2long('0.0.0.0') >> 24 == ip >> 24

    try:
        if not re.match(r"^https?://.*$", url):
            return True
        ip_address = socket.getaddrinfo(hostname, 'http')[0][4][0]
        if is_inner_ipaddress(ip_address):
            return True
    except BaseException as e:
        return False
    except:
        return False


# 生成随机请求头
def requests_headers():
    ua = random.choice(USER_AGENTS)
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': ua,
        'Cache-Control': 'max-age=0',
        'Accept-Encoding': 'gzip, deflate, sdch',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        'Cookie': "rememberMe=1; PHPSESSID=gljsd5c3ei5n813roo4878q203; sessionid=ciy76kbxozt7zeda7ug7a9fsny7d54sw"
    }
    return headers


# 页面匹配具体ico地址
def get_ico_path(context):
    soup = BeautifulSoup(context, 'lxml')
    links = soup.find_all('link')
    url = '/favicon.ico'
    for link in links:
        if link.get('rel') and 'icon' in str(link.get('rel')):
            url = link.get('href')
            break
    return url


# 获取响应信息
def get_info(target):
    """获取web的信息"""
    content = ''
    md5_ico = ''
    mmh3_ico = ''
    title = ''
    banner = ''
    scheme = 'http'
    port = 80 if target.startswith('http:') else 443
    header = ''
    server = ''
    status_code = ''
    cert = ''

    try:
        r = requests.get(url=target, headers=requests_headers(),
                         timeout=request_timeout, verify=False)
        # 获取header/server
        try:
            header = ''
            _header = r.headers
            server = _header.get('server', '')
            for k, v in _header.items():
                header += f'''{k}: {v}\n'''

        except Exception as e:
            if 'utf-8' in str(e):
                content = r.content.decode('gbk')
            else:
                logger.log('ERROR', f'get header error: {e}')
        # 获取content
        try:
            content = r.content.decode()
        except Exception as e:
            if 'utf-8' in str(e):
                content = r.content.decode('gbk')
            else:
                logger.log('ERROR', f'get content error: {e}')
        # 获取ico
        try:
            tmp_url = get_ico_path(content)
            if tmp_url.startswith('http'):
                ico_url = tmp_url
            else:
                if tmp_url.startswith('/'):
                    if target.endswith('/'):
                        ico_url = target[:-1] + tmp_url
                    else:
                        ico_url = target + tmp_url
                else:
                    if target.endswith('/'):
                        ico_url = target + tmp_url
                    else:
                        ico_url = f'{target}/{tmp_url}'
            r = requests.get(url=ico_url, headers=requests_headers(),
                             timeout=request_timeout, verify=False)
            md5_ico = str(hashlib.md5(r.content).hexdigest())
            mmh3_ico = str(mmh3.hash(codecs.lookup('base64').encode(r.content)[0]))
        except Exception as e:
            logger.log('ERROR', f'get ico_hash error: {e}')
        # 获取title
        try:
            tmp_title = BeautifulSoup(content, 'lxml').title
            if tmp_title:
                title = tmp_title.text.strip().strip('\n')
        except Exception as e:
            logger.log('ERROR', f'get title error: {e}')
        # 获取host及端口
        _url = urlparse(target)
        hostname = _url.hostname
        port = _url.port if _url.port is not None else port
        scheme = _url.scheme
        # 获取banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((hostname, port))
            ready = select.select([sock], [], [], 1)
            if ready[0]:
                banner = sock.recv(1024).decode()
                sock.close()
        except Exception as e:
            banner = ''
            logger.log('ERROR', f' get banner error: {e}')
        # 获取status_code
        try:
            status_code = r.status_code
        except Exception as e:
            status_code = '-1'
            logger.log('ERROR', f' get status_code error: {e}')
        # 获取cert信息
        try:
            if port == 443:
                cert = cert_helper.CertInfo(target)
        except Exception as e:
            logger.log('ERROR', f' get cert error: {e}')
    except Exception as err:
        logger.log('ERROR', f' get_info error: {err}')
    finally:
        return cert, status_code, header, content, title, md5_ico, mmh3_ico, banner, scheme, server, port


# wappalyzer 识别指纹
def wappalyzer_banner(url):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url, verify=False)
        webprints = wappalyzer.analyze(webpage)
        if len(webprints) > 0:
            return list(webprints)
        else:
            return []
    except Exception as e:
        logger.log('ERROR', f'Wappalyzer error: {e}')
        return []


# 判断存活
def is_alive(url):
    try:
        requests.get(url, headers=requests_headers(), verify=False, timeout=request_timeout)
        return True
    except Exception as e:
        return False


# 指纹识别
def FingerScan(target_url, finger_dic, waf):
    # 匹配body
    def body_contains(pattern):
        if '(.*)' in pattern or pattern.startswith('(?<=') or (pattern.startswith('(') and '|' in pattern):
            try:
                return re.search(pattern, body, re.M | re.I)
            except Exception as err:
                logger.log('ERROR', f'body_contains error: {err}')
        return pattern.lower() in body.lower()

    # 匹配title
    def title_contains(pattern):
        if '(.*)' in pattern or pattern.startswith('(?<=') or (pattern.startswith('(') and '|' in pattern):
            try:
                return re.search(pattern, title, re.M | re.I)
            except Exception as err:
                logger.log('ERROR', f'title_contains error: {err}')
        return pattern.lower() in title.lower()

    # 匹配协议
    def protocol_contains(pattern):
        return pattern.lower() in scheme.lower()

    # 匹配sock banner
    def banner_contains(pattern):
        return pattern.lower() in banner.lower()

    # 匹配header
    def header_contains(pattern):
        if '(.*)' in pattern or pattern.startswith('(?<=') or (pattern.startswith('(') and '|' in pattern):
            try:
                return re.search(pattern, header, re.M | re.I)
            except Exception as err:
                logger.log('ERROR', f'header_contains error: {err}')
        return pattern.lower() in header.lower()

    # 匹配证书
    def cert_contains(pattern):
        return pattern.lower() in cert.lower()

    # 匹配server
    def server_contains(pattern):
        return pattern.lower() in server.lower()

    # 匹配端口
    def port_contains(pattern):
        return int(pattern) == port

    # 匹配ico
    def ico_contents(pattern):
        if '|' in pattern:
            try:
                return re.search(pattern, md5_ico, re.M | re.I)
            except Exception as err:
                logger.log('ERROR', f'ico_contents error: {err}')
        elif len(pattern) >= 30:
            return pattern.lower() == md5_ico
        return pattern == mmh3_ico

    # 匹配状态码
    def status_contains(pattern):
        return pattern.lower() == str(status_code)

    if waf:
        product_list = []
        for vuln in vuln_list:
            vuln_url = vuln % target_url
            cert, status_code, header, body, title, md5_ico, mmh3_ico, banner, scheme, server, port = get_info(vuln_url)
            product_tmp = []
            for product, Condition in finger_dic.items():
                try:
                    for i in not_list:
                        Condition = Condition.replace(i, f'not {i[1:]}').strip()
                    if eval(Condition.strip()):
                        product_tmp.append(product)
                except Exception as e:
                    logger.log('ERROR', f'WafScan error: {e} .Condition: {Condition}')
            product_list.extend(product_tmp)
        return product_list
    else:
        cert, status_code, header, body, title, md5_ico, mmh3_ico, banner, scheme, server, port = get_info(target_url)
        product_list = []
        for product, Condition in finger_dic.items():
            try:
                for i in not_list:
                    Condition = Condition.replace(i, f'not {i[1:]}').strip()
                if eval(Condition.strip()):
                    product_list.append(product)
                    pass
            except Exception as e:
                logger.log('ERROR', f'FingerScan error: {e} .Condition: {Condition}')

        return product_list


# 任务
def task_run(target_url, finger_dic, waf=False):
    result = []
    finger_tmp = []
    start = datetime.datetime.now()
    try:
        if not check_url(target_url):
            logger.log('INFOR', f'Current Task: {target_url} ')
            finger = FingerScan(target_url, finger_dic, waf)
            finger.extend(wappalyzer_banner(target_url))
            # 去重
            for f in finger:
                f_tmp = f.replace('-', ' ').replace('_', ' ')
                if f_tmp.lower() not in finger_tmp:
                    finger_tmp.append(f_tmp.lower())
                    result.append(f_tmp.replace(' ', '-'))
        else:
            logger.log('ALERT', 'URL地址错误')
    except Exception as e:
        logger.log('ERROR', f'Finger error: {e}')
    finally:
        logger.log('INFOR', f'{target_url}: {list(set(result))}')
        logger.log('INFOR', f'Time Used: {(datetime.datetime.now() - start).seconds} 秒')
        return list(set(result))


if __name__ == "__main__":
    task_run("https://116.236.96.14:9443/", json.loads(open('finger.json', 'r').read()))
