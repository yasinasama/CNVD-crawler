
'''
该模块主要处理http://www.cnvd.org.cn

解析统计查询中的共享数据xml
'''

import os
from queue import Queue
from datetime import datetime
import threading

import requests
from bs4 import BeautifulSoup
# import pytesseract
# from PIL import Image
import pandas as pd

import xml.etree.ElementTree as ET


class CNVD:

    LOGIN_URL = 'http://www.cnvd.org.cn/user/login'
    DO_LOGIN_URL = 'http://www.cnvd.org.cn/user/doLogin/loginForm'
    CODE_URL = 'http://www.cnvd.org.cn/common/myCodeNew'

    def __init__(self,email,password):
        self.email = email
        self.password = password

        self.session = requests.Session()

        self.cookies = None

        self.login_headers = {
            'Host'            : 'www.cnvd.org.cn',
            'User-Agent'      : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
            'Accept'          : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding' : 'gzip, deflate',
            'Accept-Language' : 'zh-CN,zh;q=0.9'
        }
        self.do_login_headers = {
            'Host'                     : 'www.cnvd.org.cn',
            'Connection'               : 'keep-alive',
            'Content-Length'           : '80',
            'Cache-Control'            : 'max-age=0',
            'Origin'                   : 'http://www.cnvd.org.cn',
            'Upgrade-Insecure-Requests': '1',
            'Referer'                  :'http://www.cnvd.org.cn/user/login',
            'Content-Type'             : 'application/x-www-form-urlencoded',
            'User-Agent'               : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
            'Accept'                   : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding'          : 'gzip, deflate',
            'Accept-Language'          : 'zh-CN,zh;q=0.9'
        }
        self.code_headers = {
            'Host': 'www.cnvd.org.cn',
            'Connection': 'keep-alive',
            'Referer': 'http://www.cnvd.org.cn/user/login',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
            'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        }

    def set_session(self):
        r = self.session.get(url=self.LOGIN_URL,
                             headers=self.login_headers)
        self.cookies = r.cookies.items()
        return self

    def download_code(self):
        r = self.session.get(url=self.CODE_URL,
                             headers=self.code_headers,
                             stream=True)
        if r.status_code == 200:
            with open('bb.jpg','wb') as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)

    def do_login(self):
        # self.set_session().download_code()

        data = {
            'email': self.email,
            'passwordHidden': self.password,
            'myCode': ''
        }
        r = self.session.post(url=self.DO_LOGIN_URL,
                              headers=self.do_login_headers,
                              data=data,
                              cookies=self.cookies)
        print(r.text)

# def convert_Image(img, standard=127.5):
#     '''
#     【灰度转换】
#     '''
#     image = img.convert('L')
#
#     '''
#     【二值化】
#     根据阈值 standard , 将所有像素都置为 0(黑色) 或 255(白色), 便于接下来的分割
#     '''
#     pixels = image.load()
#     for x in range(image.width):
#         for y in range(image.height):
#             if pixels[x, y] > standard:
#                 pixels[x, y] = 255
#             else:
#                 pixels[x, y] = 0
#     return image


def xml2df(df,p=''):
    '''
    @author： cj
    @date: 20190225
    @函数：xml2df
    @参数：q:xml文件路径
    @描述：漏洞平台共享xml解析
    @返回：df表
    @示例：a=@udf CNVD.xml2df with q
    '''
    rootpath = '/opt/openfea/workspace'
    path = os.path.join(rootpath,p.strip())

    if not os.path.exists(path):
        raise Exception('文件不存在!')

    tree = ET.ElementTree(file=path)
    root = tree.getroot()

    result = []
    keys = set()
    for e in root:
        d = {}
        df2dict(e,d)
        keys |= set(d.keys())
        result.append(d)
    return pd.DataFrame(result,columns=keys)


def df2dict(node,rdict):
    if len(node) > 0:
        for element in node:
            df2dict(element,rdict)
    else:
        _key = node.tag
        _text = node.text.strip()
        if _key in rdict:
            _value = rdict[_key]
            if isinstance(_value,list):
                rdict[_key].append(_text)
            else:
                rdict[_key] = [_value,_text]
        else:
            rdict[_key] = _text





class CNVD_spider:
    VULN_ID = {
        '27': '操作系统漏洞',
        '28': '应用程序漏洞',
        '29': 'WEB应用漏洞',
        '30': '数据库漏洞',
        '31': '网络设备漏洞',
        '32': '安全产品漏洞',

    }
    HEADERS = {
        'Host': 'www.cnvd.org.cn',
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9'
    }

    def __init__(self,vid,start,end):
        self.vid = vid
        self.start = self.str2datetime(start)
        self.end = self.str2datetime(end)

        # 返回条数
        self.max = 100
        # get_detail_urls中的访问次数
        self.count = 0

        # 这边开5个线程
        self.thread_num = 5
        self.session = requests.Session()
        self.vuln_urls = Queue()

    def str2datetime(self,s):
        if isinstance(s,str):
            if '-' in s:
                fmt = '%Y-%m-%d'
            else:
                fmt = '%Y%m%d'
            return datetime.strptime(s,fmt)
        elif isinstance(s,datetime):
            return s

    def get_detail_urls(self):
        url = 'http://www.cnvd.org.cn/flaw/typeResult?typeId=%s&max=%s&offset=%s'%(self.vid,self.max,self.max*self.count)
        while True:
            html = self.session.post(url=url, headers=self.HEADERS).text
            # 同一个http请求10次会触发反爬,因此这边重建连接
            if not html:
                self.session = requests.Session()
                continue
            soup = BeautifulSoup(html, "html.parser")
            tbody = soup.find('tbody').find_all('tr')
            try:
                for tr in tbody:
                    publish_time = tr.find_all('td')[-1].text.strip()
                    if publish_time:
                        publish_time_date = self.str2datetime(publish_time)
                        if publish_time_date >= self.start:
                            if publish_time_date <= self.end:
                                vuln_url = tr.td.find('a').get('href')
                                if vuln_url:
                                    self.vuln_urls.put('http://www.cnvd.org.cn'+vuln_url)
                        else:
                            break
                else:
                    self.count += 1
                    self.get_detail_urls()
            except:
                raise Exception('出错')
            else:
                break

    def get_detail_info(self,session,result):
        while not self.vuln_urls.empty():
            url = self.vuln_urls.get()
            while True:
                html = session.get(url=url,headers=self.HEADERS).text
                # 同一个http请求10次会触发反爬,因此这边重建连接
                if not html:
                    session = requests.Session()
                    continue
                soup = BeautifulSoup(html,"html.parser")
                try:
                    vuln_title = soup.find(class_='blkContainerSblk').h1.text
                    d = {'title':vuln_title,'type':self.VULN_ID[self.vid]}
                    tbody = soup.find('tbody').find_all('tr')
                    for tr in tbody[:-2]:
                        tds = tr.find_all('td')
                        key = tds[0].text.strip()
                        value = tds[1].text.strip()
                        # 这边字符串要特殊处理
                        if key == '危害级别':
                            value = value.split()[0].strip()
                        d[key] = value
                    result.append(d)
                    break
                except:
                    raise Exception('出错')
            self.vuln_urls.task_done()
        return result

    def run(self,r):
        threads = []
        for _ in range(self.thread_num):
            t = threading.Thread(target=self.get_detail_info,args=(requests.Session(),r))
            threads.append(t)

        for i in threads:
            i.start()

        for i in threads:
            i.join()

        self.vuln_urls.join()


if __name__=='__main__':
    r = []
    cnvd = CNVD_spider('31','20190222','20190227')
    cnvd.get_detail_urls()
    cnvd.run(r)
    print(r)