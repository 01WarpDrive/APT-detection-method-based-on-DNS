# 将zeek数据集dns.log转换为json格式，
# 每条dns记录提取主机ip、时间、查询域名三个特征，整理成字典，汇总为数组
# 按顺序提取dns记录，根据记录数命名json

import json

num = 10000

flows = []
with open('conn.log.labeled', 'r', encoding='utf-8') as f:
    for i in range(8): # 跳过备注内容 8
        tmp = f.readline()
        print(tmp)
    for i in range(num): # 读取的条目数量
        content = f.readline()
        # print(content)
        if content == "":
            continue
        element = content.split()
        if element[13] != "A": # A类型
            continue
        flow = {"src_ip": element[2], "start_time": element[0], "domain": element[9]}
        flows.append(flow)



with open(f"./json/dns_flow_{num}.json", "w") as fp: ## 转化后的json文件
    json.dump(flows, fp)