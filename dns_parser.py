### 将目标pcap文件转化为json文件，读取处理DNS记录
__author__ = 'jmh'
import os
dns_query = "dns.qry.name"

dns_response_name = "dns.resp.name"
dns_response_type = "dns.resp.type"
dns_response_class = "dns.resp.class"
dns_response_address = "dns.a"
dns_response_name_server = "dns.ns"
dns_response_cname = "dns.cname"


typeid2str={
    "5":"CNAME",
    "1":"A",
    "2":"NS"
}
from flowcontainer import extractor
def dns_basic_parser(pfile):
    extension = [dns_query,
                 dns_response_name,
                 dns_response_type,
                 dns_response_class,
                 dns_response_address,
                 dns_response_name_server,
                 dns_response_cname
    ]
    dns_flows = extractor.extract(infile=pfile,
                                  filter="dns",
                                  extension=extension
            )
    flows =[]
    for each in dns_flows:
        try:
            ##print(dns_flows[each])
            flow = {} ##flow ={'pcapname': os.path.basename(pfile) }
            flow["src_ip"] = dns_flows[each].src
            ##flow["sport"] = dns_flows[each].sport
            ##flow["dst_ip"] = dns_flows[each].dst
            ##flow["dport"] = dns_flows[each].dport
            ##flow["protocol"] = dns_flows[each].protocol
            ##flow['ext_proto'] =dns_flows[each].ext_protocol
            flow["start_time"] = int(dns_flows[each].time_start)
            ##flow["end"] = int(dns_flows[each].time_end)
            names = []
            types = []
            classes = []
            addresses = []
            name_servers = []
            cnames = []

            if dns_response_name in dns_flows[each].extension:
                names  = dns_flows[each].extension[dns_response_name][0][0].split(",")

            if dns_response_type in dns_flows[each].extension:
                types = dns_flows[each].extension[dns_response_type][0][0].split(",")

            if dns_response_class in dns_flows[each].extension:
                classes = dns_flows[each].extension[dns_response_class][0][0].split(",")

            if dns_response_address in dns_flows[each].extension:
                addresses = dns_flows[each].extension[dns_response_address][0][0].split(",")

            if dns_response_name_server in dns_flows[each].extension:
                name_servers = dns_flows[each].extension[dns_response_name_server][0][0].split(",")

            if dns_response_cname in dns_flows[each].extension:
                cnames = dns_flows[each].extension[dns_response_cname][0][0].split(",")

            records = []
            names_id = 0
            addresses_id = 0
            cnames_id = 0
            name_servers_id = 0

            domain = ""
            for _value in types:
                if _value not in ['1', '5', '2']:
                    continue
                if _value == '1':#只过滤a记录
                    domain = names[names_id]
                    break
                names_id += 1

            if domain != "":
                flow['domain'] = domain
                flows.append(flow)
        except BaseException as exp:
            print(exp)
            print(dns_flows[each])
    return flows


if __name__ == '__main__':
    dns_flows = dns_basic_parser(pfile="./pcap/test.pcap") ## 目标pcap文件
    for each in dns_flows:
        print(each)
    print(len(dns_flows))

    import  json
    with open("./json/dns_flow.json","w") as fp: ## 转化后的json文件
       json.dump(dns_flows, fp)