# luadns
Lua dns resolver, supports udp/tcp, supports ECS (edns-client-subnet).

###运行example
local host = "www.google.com"
local server = "8.8.8.8"
local port = 53
local timeout = 3
local subnet = "111.111.111.111/24"
dns = get_dns_resolver(host,server,port,timeout,"udp",false,subnet)
print("udp,no subnet")
if dns then for i,v in pairs(dns) do print(v) end end
dns = get_dns_resolver(host,server,port,timeout,"udp",true,subnet)
print("\nudp,with subnet")
if dns then for i,v in pairs(dns) do print(v) end end
dns = get_dns_resolver(host,server,port,timeout,"tcp",false,subnet)
print("\ntcp,no subnet")
if dns then for i,v in pairs(dns) do print(v) end end
dns = get_dns_resolver(host,server,port,timeout,"tcp",true,subnet)
print("\ntcp,with subnet")
if dns then for i,v in pairs(dns) do print(v) end end

###运行结果
udp,no subnet
216.58.200.36

udp,with subnet
172.217.24.4

tcp,no subnet
74.125.68.105
74.125.68.104
74.125.68.106
74.125.68.103
74.125.68.147
74.125.68.99

tcp,with subnet
216.58.196.228

###总结
直接使用udp连接，有被抢答的可能，建议使用tcp连接
