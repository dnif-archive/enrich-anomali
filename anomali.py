import requests
import json
import yaml
import os
import datetime
import logging


inteltype = ['INTEL_ADDR','INTEL_URL','INTEL_DOMAIN','INTEL_FILE_HASH','INTEL_EMAIL']
path = os.environ["WORKDIR"]

try:
    with open(path + "/enrichment_plugins/anomali/dnifconfig.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
except Exception, e:
    logging.error("ANOMALI enrichment error in reading dnifconfig.yml: {}".format(e))


def read_file_marker():
    try:
        with open(path+"/enrichment_plugins/anomali/feedtimer.txt", 'r') as redcnt:
            d = redcnt.read()
            counter_date = datetime.datetime.strptime(d, "%Y-%m-%d %H:%M")
            dt = datetime.datetime.now()
            day = dt.strftime("%Y-%m-%d")
            date = "{} {:02d}:{:02d}".format(day, dt.hour, dt.minute)
            now = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M")
            final = (now - counter_date).seconds / 60
            if final<=10:
                checker = False
                status = True
            else:
                checker = True
                status = data_injest(checker)
                if status == True:
                    dt = datetime.datetime.now()
                    day = dt.strftime("%Y-%m-%d")
                    date = "{} {:02d}:{:02d}".format(day, dt.hour, dt.minute)
                    with open(path + "/enrichment_plugins/anomali/feedtimer.txt", 'w') as wrcnt:
                        wrcnt.write(str(date))
    except IOError as e:
        checker = True
        status = data_injest(checker)
        if status == True:
            dt = datetime.datetime.now()
            day = dt.strftime("%Y-%m-%d")
            date = "{} {:02d}:{:02d}".format(day, dt.hour, dt.minute)
            with open(path+"/enrichment_plugins/anomali/feedtimer.txt", 'w') as wrcnt:
                wrcnt.write(str(date))
    except Exception as e:
        logging.error("ANOMALI enrichment  error : {}".format(e))
    return status


def data_injest(status=False):
    arr_url = []
    arr_ip = []
    arr_md5 = []
    arr_domain = []
    arr_email = []
    try:
        if status == True:
            headers = {"Conent-Type": "application/json"}
            try:
                res = requests.get(cfg['enrich_plugin']['FEED_URL'], headers=headers, verify=False)
                json_response = res.json()
            except Exception,e:
                logging.error(" AL API Request Error : {}".format(e))
            for i in json_response:
                if i['type'] == "ip":
                    arr_ip.append(i)
                elif i['type'] == "domain":
                    arr_domain.append(i)
                elif i['type'] == "url":
                    arr_url.append(i)
                elif i['type'] == "md5":
                    arr_md5.append(i)
                else:
                    arr_email.append(i)
            ind_dict = {}
            ind_dict['ip'] = arr_ip
            ind_dict['domain'] = arr_domain
            ind_dict['url'] = arr_url
            ind_dict['md5'] = arr_md5
            ind_dict['email'] = arr_email
            indlst=['ip','domain','url','md5','email']
            for tname in indlst:
                with open(path+"/enrichment_plugins/anomali/intel_{}.json".format(tname),"w") as f:
                    json.dump(ind_dict[tname],f)
            checker = True
    except Exception as e:
        checker = False
        logging.error(" ANOMALI API  local data write error : {}".format(e))
    return checker


def import_url_intel():
    try:
        d = read_file_marker()
        if d == True:
            with open(path+"/enrichment_plugins/anomali/intel_url.json","r") as f1:
                url_lst = json.load(f1)
            try:
                lines = []
                for line in url_lst:
                    tmp_dict = {}
                    tmp_dict["EvtType"] = "URL"
                    tmp_dict["EvtName"] = line['value']
                    tmp_dict2 = {}
                    tmp_dict2["IntelRef"] = ["ANOMALI"]
                    tmp_dict2["IntelRefURL"] = [""]
                    data = str(line['itype'])
                    data = data.title()
                    data = data.replace("_", " ")
                    tmp_dict2["ALThreatType"] = [data]
                    tmp_dict2["ALConfidence"] = [line["confidence"]]
                    tmp_dict2["ALSeverity"] = [line["severity"]]
                    tmp_dict2["ALSource"] = [line["source"]]
                    tmp_dict2["ALClassification"]=[line["classification"]]
                    if line["maltype"]!=None:
                        tmp_dict2["ALMalType"]=[line["maltype"]]
                    if line["tags"] != None:
                        tmp_dict2["ALTags"] = [line["tags"]]
                    tmp_dict2["ALModifiedTstamp"]=[line["modified_ts"]]
                    tmp_dict2["ALStatus"] =[line["status"]]
                    tmp_dict["AddFields"] = tmp_dict2
                    lines.append(tmp_dict)
            except Exception,e:
                lines = []
    except Exception,e:
        logging.error("ANOMALI API error in import_url_intel :{}".format(e))
    return lines,"INTEL_URL"


def import_domain_intel():
    try:
        d = read_file_marker()
        if d == True:
            with open(path+"/enrichment_plugins/anomali/intel_domain.json","r") as f1:
                url_lst = json.load(f1)
            try:
                lines = []
                for line in url_lst:
                    tmp_dict = {}
                    tmp_dict["EvtType"] = "DOMAIN"
                    tmp_dict["EvtName"] = line['value']
                    tmp_dict2 = {}
                    tmp_dict2["IntelRef"] = ["ANOMALI"]
                    tmp_dict2["IntelRefURL"] = [""]
                    data = str(line['itype'])
                    data = data.title()
                    data = data.replace("_", " ")
                    tmp_dict2["ALThreatType"] = [data]
                    tmp_dict2["ALConfidence"] = [line["confidence"]]
                    tmp_dict2["ALSeverity"] = [line["severity"]]
                    tmp_dict2["ALSource"] = [line["source"]]
                    tmp_dict2["ALClassification"]=[line["classification"]]
                    if line["maltype"]!=None:
                        tmp_dict2["ALMalType"]=[line["maltype"]]
                    if line["tags"]!=None:
                        tmp_dict2["ALTags"] = [line["tags"]]
                    tmp_dict2["ALModifiedTstamp"]=[line["modified_ts"]]
                    tmp_dict2["ALStatus"] =[line["status"]]
                    tmp_dict["AddFields"] = tmp_dict2
                    lines.append(tmp_dict)
            except Exception,e:
                lines = []
    except Exception,e:
        logging.error("ANOMALI API error in import_domain_intel :{}".format(e))
    return lines,"INTEL_DOMAIN"


def import_hash_intel():
    try:
        d = read_file_marker()
        if d == True:
            with open(path+"/enrichment_plugins/anomali/intel_md5.json","r") as f1:
                url_lst = json.load(f1)
            try:
                lines = []
                for line in url_lst:
                    tmp_dict = {}
                    tmp_dict["EvtType"] = "FILEHASH"
                    tmp_dict["EvtName"] = line['value']
                    tmp_dict2 = {}
                    tmp_dict2["IntelRef"] = ["ANOMALI"]
                    tmp_dict2["IntelRefURL"] = [""]
                    data = str(line['itype'])
                    data = data.title()
                    data = data.replace("_", " ")
                    tmp_dict2["ALThreatType"] = [data]
                    tmp_dict2["ALConfidence"] = [line["confidence"]]
                    tmp_dict2["ALSeverity"] = [line["severity"]]
                    tmp_dict2["ALSource"] = [line["source"]]
                    tmp_dict2["ALClassification"]=[line["classification"]]
                    if line["maltype"]!=None:
                        tmp_dict2["ALMalType"]=[line["maltype"]]
                    if line["tags"] != None:
                        tmp_dict2["ALTags"] = [line["tags"]]
                    tmp_dict2["ALModifiedTstamp"]=[line["modified_ts"]]
                    tmp_dict2["ALStatus"] =[line["status"]]
                    tmp_dict["AddFields"] = tmp_dict2
                    lines.append(tmp_dict)
            except Exception,e:
                lines = []
    except Exception,e:
        logging.error("ANOMALI API error in import_hash_intel :{}".format(e))
    return lines,"INTEL_FILE_HASH"


def import_email_intel():
    try:
        d = read_file_marker()
        if d == True:
            with open(path+"/enrichment_plugins/anomali/intel_email.json","r") as f1:
                url_lst = json.load(f1)
            try:
                lines = []
                for line in url_lst:
                    tmp_dict = {}
                    tmp_dict["EvtType"] = "Email"
                    tmp_dict["EvtName"] = line['value']
                    tmp_dict2 = {}
                    tmp_dict2["IntelRef"] = ["ANOMALI"]
                    tmp_dict2["IntelRefURL"] = [""]
                    data = str(line['itype'])
                    data = data.title()
                    data = data.replace("_", " ")
                    tmp_dict2["ALThreatType"] = [data]
                    tmp_dict2["ALConfidence"] = [line["confidence"]]
                    tmp_dict2["ALSeverity"] = [line["severity"]]
                    tmp_dict2["ALSource"] = [line["source"]]
                    tmp_dict2["ALClassification"]=[line["classification"]]
                    if line["maltype"]!=None:
                        tmp_dict2["ALMalType"]=[line["maltype"]]
                    if line["tags"] != None:
                        tmp_dict2["ALTags"] = [line["tags"]]
                    tmp_dict2["ALModifiedTstamp"]=[line["modified_ts"]]
                    tmp_dict2["ALStatus"] =[line["status"]]
                    tmp_dict["AddFields"] = tmp_dict2
                    lines.append(tmp_dict)
            except Exception,e:
                lines = []
    except Exception,e:
        logging.error("ANOMALI API error in import_email_intel :{}".format(e))
    return lines,"INTEL_EMAIL"


def import_ip_intel():
    try:
        d = read_file_marker()
        if d == True:
            with open(path+"/enrichment_plugins/anomali/intel_ip.json","r") as f1:
                url_lst = json.load(f1)
            try:
                lines = []
                for line in url_lst:
                    tmp_dict = {}

                    tmp_dict["EvtName"] = line['value']
                    if '.' in line['value']:
                        tmp_dict["EvtType"] = "IPv4"
                    else:
                        tmp_dict["EvtType"] = "IPv6"
                    tmp_dict2 = {}
                    tmp_dict2["IntelRef"] = ["ANOMALI"]
                    tmp_dict2["IntelRefURL"] = [""]
                    data = str(line['itype'])
                    data = data.title()
                    data = data.replace("_", " ")
                    tmp_dict2["ALThreatType"] = [data]
                    tmp_dict2["ALConfidence"] = [line["confidence"]]
                    tmp_dict2["ALSeverity"] = [line["severity"]]
                    tmp_dict2["ALSource"] = [line["source"]]
                    tmp_dict2["ALClassification"]=[line["classification"]]
                    tmp_dict2["ALModifiedTstamp"]=[line["modified_ts"]]
                    if line["maltype"]!=None:
                        tmp_dict2["ALMalType"]=[line["maltype"]]
                    if line["tags"] != None:
                        tmp_dict2["ALTags"] = [line["tags"]]
                    tmp_dict2["ALStatus"] =[line["status"]]
                    tmp_dict["AddFields"] = tmp_dict2
                    lines.append(tmp_dict)
            except Exception,e:
                lines = []
    except Exception,e:
        logging.error("ANOMALI API error in import_ip_intel :{}".format(e))
    return lines,"INTEL_ADDR"
