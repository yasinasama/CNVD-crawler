

import os
import requests
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




if __name__=='__main__':
    path = '/Users/yasina/Downloads/2019-02-04_2019-02-10.xml'
    # tree = ET.ElementTree(file=path)
    # root = tree.getroot()
    # result = []
    # for i in root:
    #     d = {}
    #     df2dict(i,d)
    #     print(list(d.keys()))
    # print(result)
    # email = '614867000@qq.com'
    # password = 'oPxGqC80A71jW4MjmKduvA=='
    # cnvd = CNVD(email,password)
    # cnvd.set_session().download_code()
    # cnvd.do_login()
    # img = convert_Image(Image.open('bb.jpg'))
    # code = pytesseract.image_to_string(img)