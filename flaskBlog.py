#!/usr/bin/python
# -*- coding:utf-8 -*-

from flask import Flask
from flask import redirect
from flask import request
from flask import render_template
from flask_script import Manager


import datetime
import chartkick

import os
import time
import re
import linecache




BASE_DIR= os.path.split(os.path.realpath(__file__))[0]
UPLOAD_PATH = os.path.join(BASE_DIR, "uploads")

app = Flask(__name__)
app.jinja_env.add_extension("chartkick.ext.charts")
app.config['SECRET_KEY']='onepiece'


#上传相关配置

ALLOWED_EXTENSIONS = {'txt', 'log'}

manager = Manager(app)

# #全局变量
needlist = []


#将apache, nginx iis日志转化为二维列表
def log2list(file_name):

    needlist = []

    line_one = linecache.getline(file_name, 6).split(" ")[0]

    re_ip = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')

    if re.match(re_ip, line_one):

        with open(file_name) as file:
            for line in file:
                if line[0] != "#":
                    app = re.split(" ", line)

                    request_time = app[3].replace("[", "")
                    request_method = app[5]
                    request_tmp = app[6].split("?")

                    if len(request_tmp) == 2:
                        request_url, request_param = request_tmp
                    else:
                        request_url = request_tmp[0]
                        request_param = "-"

                    request_ip = app[0]

                    if app[11] != "\"-\"":

                        request_ua = "+".join(app[11:]).strip("\n")
                    else:
                        request_ua = "+".join(app[11:]).replace("\"-\"", "").replace("+", "", 1).strip("\n")

                    request_code = app[8]

                    needlist.append([request_time, request_method, request_url, request_param, request_ip, request_ua, request_code])




    else:

        with open(file_name) as file:
             for line in file:

                if line[0] != "#":
                    app = re.split(" ", line)

                    app_time = app[0] + "_" + app[1]

                    needlist.append([app_time, app[3], app[4], app[5], app[8], app[9], app[10]])

    return needlist



#用来返回url次数
def get_url_array(needlist):
    url_list = []

    # 提取可执行文件
    exec_file = r'\.js$|\.css$|\.jpg$|\.png$|\.gif$|.ico$|\.woff|\.doc|\.txt|\.doc|\.swf|\.xls|\.pdf|\.ppt'



    for i in needlist:
        if i[6] != "404":
            sqli_response = re.findall(exec_file, i[2], re.I)

            if not sqli_response:
                url_list.append(i[2])


    #url_list = [x[2] for x in needlist]

    d = {k: url_list.count(k) for k in set(url_list)}

    url_array = sorted(d.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)


    if len(url_array) <11:
        ran = len(url_array)
    else:
        ran=11

    #选取前10
    ten_dict = dict([url_array[i] for i in range(ran)])


    return ten_dict, url_array


##返回IP访问次数排序
def get_ip_array(needlist):
    # 提取可执行文件
    exec_file = r'\.js$|\.css$|\.jpg$|\.png$|\.gif$|.ico$|\.woff'

    ip_list = []

    for i in needlist:
        if  i[6] != "404":
            sqli_response = re.findall(exec_file, i[2], re.I)

            if not sqli_response:
                ip_list.append(i[4])



    #
    # ip_list = [x[4] for x in needlist]
    #
    d = {k: ip_list.count(k) for k in set(ip_list)}


    #按照访问次数排列
    ip_array = sorted(d.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)

    if len(ip_array) <11:
        ran = len(ip_array)
    else:
        ran=11

    #选取前10
    ten_dict = dict([ip_array[i] for i in range(ran)])



    return ten_dict, ip_array

#UA信息
def get_ua_list(needlist):
    sqli_list = []

    #d = {k: needlist.count(k) for k in set(needlist)}

    for i in needlist:
        sqli_list.append(i[5])

    d = {k: sqli_list.count(k) for k in set(sqli_list)}

    ua_array = sorted(d.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)

    return ua_array



#用来返回ua次数
def get_ua_array(needlist):

    ua_list = [x[5] for x in needlist]

    d = {k: ua_list.count(k) for k in set(ua_list)}

    ua_array = sorted(d.items(), lambda x, y: cmp(x[1], y[1]), reverse=True)



    return ua_array



#用来统计UA信息
def analyse_ua(needlist):

    len_log= len(needlist)

    system_dict = {}
    browser_dict = {}
    else_dict = {}


    ua_list = [x[5] for x in needlist]
    for line in ua_list:
        sys_preg = re.compile('Macintosh|Windows|iPhone|Android|Unix|Ubuntu|iPad', re.IGNORECASE)

        sysret = sys_preg.search(line)

        if sysret:
            syskey = sysret.group()
            system_dict[syskey] = system_dict.get(syskey, 1) + 1

        browser_preg = re.compile('Safari|Maxthon|360browser|Opera|UC|Chrome|Firefox|Trident|Baiduspider|Googlebot', re.IGNORECASE)
        broret = browser_preg.search(line)
        if broret:
            brokey = broret.group()
            browser_dict[brokey] = browser_dict.get(brokey, 1) + 1


        else_preg = re.compile('HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqln|-scan|hydra|Parser|libwww|BBBike|sqlmap|w3af|owasp|Nikto|fimap|havij|PycURL|scapy|request|curl|httperf|bench|urrlib|wget', re.IGNORECASE)

        elseret = else_preg.search(line)
        if elseret:
            elsekey = elseret.group()
            else_dict[elsekey] = else_dict.get(elsekey, 1) + 1

    system_else = sum(value for obj, value in system_dict.items())

    browser_else = sum(value for obj, value in browser_dict.items())


    system_dict['else'] = len_log- system_else

    browser_dict["else"] = len_log - browser_else



    return system_dict, browser_dict, else_dict


#用来检测攻击信息
def attack_analy(needlist):


    sqli_list = []
    xss_list = []
    sen_list = []

    #攻击检测正则表达式
    sql = r'select.*from|insert|delete|update|create|where|union|destory|drop|alter|like|exec|count|chr|mid|master|truncate|char|declare '

    xss = r'alert|^script$|<|>|%3E|%3c|&#x3E|\u003c|\u003e|&#x'

    sen = r'\.pl|\.sh|\.do|\.action|zabbix|phpinfo|/var/|/opt/|/local/|/etc|/apache/|\.log|invest\b|\.xml|apple-touch-icon-152x152|\.zip|\.rar|\.asp\b|\.php|\.bak|\.tar\.gz|\bphpmyadmin\b|admin|\.exe|\.7z|\.zip|\battachments\b|\bupimg\b|uploadfiles|templets|template|data\b|forumdata|includes|cache|jmxinvokerservlet|vhost|bbs|host|wwwroot|\bsite\b|root|hytop|flashfxp|bak|old|mdb|sql|backup|^java$|class|\.\.\/|php:\/input'

    for  i in needlist:


        if i[3] != "-":
            sqli_response = re.findall(sql, i[3], re.I)

            if len(sqli_response) != 0:
                sqli_list.append([i[0], i[2], i[3], i[4], i[5]])


            xss_response = re.findall(xss, i[3], re.I)
            if len(xss_response) != 0:
                xss_list.append([i[0], i[2], i[3], i[4], i[5]])


            sen_response = re.findall(sen, i[3], re.I)
            if len(sen_response) != 0:
                sen_list.append([i[0], i[2], i[3], i[4], i[5]])




    return sqli_list, xss_list, sen_list


#可疑木马分析
#木马的行为指纹是一个可执行文件只有一到三个ip地址访问过或者是解析漏洞，当然黑客要是把木马写到自带的可执行文件里，只能手动查杀了
def susp_trojan(need_list):

    trojan_dict = {}

    new_trojan_dict = {}
    #提取可执行文件
    exec_file = r'\.php|\.asp|\.jsp|\.aspx'


    #解析漏洞木马
    analy_rep = '.+\..{3}/.+\.php$|.+\.asp;.+\..{3}'

    for i in needlist:
        if i[2] != "/" and i[6] != "404":
            sqli_response = re.findall(exec_file, i[2], re.I)

            analy_file = re.findall(analy_rep, i[2], re.I)

            if len(sqli_response) != 0 or len(analy_file) != 0:
                trojan_dict.setdefault(i[2], set()).add(i[4])
                #if i[2] in trojan_dict.keys():

    for i in trojan_dict:
        if len(trojan_dict[i]) > 0 and len(trojan_dict[i]) < 4:
            new_trojan_dict[i] = list(trojan_dict[i])

    return new_trojan_dict


#flask文件上传操作
@app.route("/", methods=["GET", "POST"])
def upload_file():

    if request.method == "POST":

        file = request.files["file"]
        file_name = file.filename

        if '.' in file_name and file_name.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS:
            time_path = time.strftime("%m_%d_%H_%M_%S", time.localtime())

            file_path = os.path.join(UPLOAD_PATH, time_path)

            full_file = os.path.join(file_path, file_name)

            os.mkdir(file_path)
            file.save(full_file)

            global needlist

            needlist = log2list(full_file)

            return redirect('/result_page')


    return render_template("index.html")




@app.route("/result_page")
def result_analy():

    return render_template('base.html')
    # return render_template("test.html")

@app.route("/section1")
def section_fun():
    if len(needlist) == 0:
        return redirect("/")

    ip_data, ip_tmp = get_ip_array(needlist)
    url_data, url_tmp = get_url_array(needlist)




    return render_template('section1.html', ip_data=ip_data, url_data=url_data)


@app.route("/section2")
def section2_fun():
    if len(needlist) == 0:
        return redirect("/")

    system_dict, browser_dict, spider_dict = analyse_ua(needlist)


    return render_template('section2.html', system_dict=system_dict, browser_dict=browser_dict, spider_dict = spider_dict)


@app.route("/section3")
def section3_fun():
    if len(needlist) == 0:
        return redirect("/")

    trojan = susp_trojan(needlist)

    d = {k: len(trojan[k]) for k in set(trojan)}



    return render_template('section3.html', trojan_dict = d)

@app.route("/section4")
def section4_fun():
    if len(needlist) == 0:
        return redirect("/")

    #基础信息
    ip_data, ip_tmp = get_ip_array(needlist)
    url_data, url_tmp = get_url_array(needlist)
    #ua_data = get_ua_array(needlist)

    #UA信息
    ua_data = get_ua_list(needlist)


    #攻击分析
    sql_data, xss_data, else_data = attack_analy(needlist)

    #木马分析
    traojan_data = susp_trojan(needlist)

    time_path = time.strftime("%m_%d_%H_%M_%S", time.localtime())
    time_file = time_path + ".txt"



    result_log = os.path.join(BASE_DIR,"static","result",time_file)

    fl = open(result_log, 'w')
    fl.write("IP地址排序\n")
    for i in ip_tmp:

        i = " ".join('%s' % id for id in i)

        fl.write(i)
        fl.write("\n")

    fl.write("\n\n")
    fl.write("URL排序\n")
    for j in url_tmp:

        j = " ".join('%s' % id for id in j)

        fl.write(j)
        fl.write("\n")

    fl.write("\n\n")
    fl.write("UA排序\n")

    for m in ua_data:

        m = " ".join('%s' % id for id in m)

        fl.write(m)
        fl.write("\n")

    fl.write("\n\n")
    fl.write("黑客攻击\n")
    fl.write("\n")

    if len(sql_data) == 0:
        fl.write("没有发现sql攻击\n")
    else:
        fl.write("发现sql攻击\n")
        for n in sql_data:
            n = " ".join(n)

            fl.write(n)
            fl.write("\n")

    if len(xss_data) == 0:
        fl.write("没有发现xss攻击\n")
    else:
        fl.write("发现xss攻击\n")
        for o in xss_data:
            o = " ".join(o)

            fl.write(o)
            fl.write("\n")

    if len(else_data) == 0:
        fl.write("没有发现其他攻击\n")

    else:
        fl.write("发现攻击\n")
        for h in else_data:
            h = " ".join(h)
            fl.write(h)
            fl.write("\n")


    if not traojan_data:

        fl.write("\n\n")
        fl.write("没有发现疑似木马\n")

    else:
        fl.write("\n\n")
        fl.write("发现疑似木马\n")


        for l in traojan_data:
            str_trojan = l + " "+",".join(traojan_data[l])
            fl.write(str_trojan)
            fl.write("\n")


    fl.close()

    result_path = "/static/result/" + time_file


    return render_template('section4.html', result = result_path)



@app.errorhandler(404)
def page_not_found(e):

    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


if __name__ == '__main__':
    manager.run()
