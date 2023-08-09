# 提取特征向量并进行分类
# 跳过论文中筛除内部DNS服务器记录的操作
# 跳过论文中的DNS白名单筛选，直接进行特征提取和分类
# 从./json读取数据，提取特征并分类，结果输出到./txt/output.txt


import json

hosts    = [] # 涉及的主机
domains  = [] # 涉及的域
features = [] # 特征集
time_win = 5.0 # 时间窗口

C2     = [] # C2数据，包含主机、目标域、特征
normal = [] # 正常数据


def extract_features(data):
    for record in data:
        if record["src_ip"] not in hosts:
            hosts.append(record["src_ip"])
        if record["domain"] not in domains:
            domains.append(record["domain"])
    
    for k in range(len(hosts)): # 建立主机和域一一对应的DNS数据集合
        print(f"Extract Progress: {k + 1}/{len(hosts)}", end="\r")

        host_features = [] # 第k个host对应不同域的特征
        for l in range(len(domains)):
            V_k_l = {}
            C_k_l = []
            count = 0
            for i in range(len(data)):
                R_k_l_i = [] # 以data元素下标来标识DNS记录
                record = data[i]
                if record["src_ip"] != hosts[k] or record["domain"] != domains[l]:
                    continue
                time = float(record["start_time"])
                for t in range(i-1, -1, -1): # 时间窗口筛选
                    if float(data[t]["start_time"]) < time - time_win:
                        break
                    R_k_l_i.append(t)
                    count += 1
                for t in range(i+1, len(data)): # 时间窗口筛选
                    if float(data[t]["start_time"]) > time + time_win:
                        break
                    R_k_l_i.append(t)
                    count += 1
                C_k_l.append(R_k_l_i)
            # print(C_k_l)
            
            # 计算置信水平
            HC = 0
            for domain in domains:
                CI = 0
                for R in C_k_l:
                    
                    for i in R: # 检测R_k_l_i是否包含对应域的DNS记录
                        record = data[i]
                        if record["domain"] == domain:
                            CI += 1
                            break
                HC = max(HC, CI)

            # 提取特征
            if len(C_k_l) != 0:
                V_k_l["M"]  = int(len(C_k_l))
                V_k_l["AN"] = float(count / len(C_k_l))
                V_k_l["HC"] = int(HC)
                host_features.append(V_k_l)
        features.append(host_features)


def classify():
    i = 1
    t = 0
    for h in range(len(features)):
        t += len(features[h])

    for h in range(len(features)):
        for d in range(len(features[h])):
            print(f"Classify Progress: {i}/{t}", end="\r")
            i += 1

            feature = features[h][d]
            M  = feature["M"]
            AN = feature["AN"]
            HC = feature["HC"]
            if M >= 3 and AN <= 0.4:
                C2.append({"host": hosts[h], "domain": domains[d], "feature":feature})
            elif M >= 3 and AN <= 1 and HC <= 1:
                C2.append({"host": hosts[h], "domain": domains[d], "feature":feature})
            else:
                normal.append({"host": hosts[h], "domain": domains[d], "feature":feature})



# 打开包含JSON数据的文件
path = './json/dns_flow_20000.json'
with open(path, 'r') as file:
    data = json.load(file)
extract_features(data)
classify()
# for i in normal:
#     print(id)

with open('./txt/output.txt', 'a') as file:
    file.write("JSON file path: " + path + "\n")
    file.write("total hosts:    " + str(len(hosts)) + "\n")
    file.write("total domains:  " + str(len(domains)) + "\n")
    file.write("total features: " + str(len(features)) + "\n")
    file.write("C2 log number:     " + str(len(C2)) + "\n")
    file.write("normal log number: " + str(len(normal)) + "\n")
    file.write("C2 log details: \n")
    for ele in C2:
        file.write(str(ele) + "\n")
    file.write("\n")

print()
print("finish")