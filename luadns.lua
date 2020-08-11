local lsocket = require("lsocket")

function string.split(str,reps)
    if string.find(str,reps) ~= nil then
        local resultStrList = {}
        string.gsub(str,'[^'..reps..']+',function (w)
            table.insert(resultStrList,w)
        end)
        return resultStrList
    else return nil
    end
end
function str_byte(str)
    if str == nil then return end
    local list_byte={}
    for i=1,string.len(str) do
        table.insert(list_byte,string.byte(string.sub(str,i,i)))
    end
    print( table.concat(list_byte," "))
end
function str_byte_find(str,byte)
    if str == nil then return -1 end
    local index = -1
    for i=1,string.len(str) do
        if string.byte(string.sub(str,i,i)) == byte then
            index = i
        end
    end
    return index
end
function isintable(tbl,value)
    for k,v in ipairs(tbl) do
        --if v == value then
        if string.find(value,v) then
            return true
        end
    end
    return false
end
function get_queries_name(url)
    local temp = string.split(url,".")
    local queries_name = ""
    for i,v in pairs(temp) do
        queries_name = queries_name .. string.char(string.len(v))
        for j=1,string.len(v) do
            queries_name = queries_name .. string.sub(v,j,j)
        end
    end
    return queries_name .. string.char(0x00)
end
function get_host_address_mask(host)
    if string.find(host,"%d+%.%d+%.%d+%.%d+/%d+") ~= nil then
        local temp = string.split(host,"/")
        local mask = tonumber(temp[2])
        local tt = string.split(temp[1],".")
        local csubnet_client_subnet
        if mask <= 8 then
            csubnet_client_subnet = string.char(tt[1])
        elseif mask <= 16 then
            csubnet_client_subnet = string.char(tt[1],tt[2])
        elseif mask <= 24 then
            csubnet_client_subnet = string.char(tt[1],tt[2],tt[3])
        else
            csubnet_client_subnet = string.char(tt[1],tt[2],tt[3],tt[4])
        end
        return csubnet_client_subnet,mask
    end
    return nil
end
function set_dns_query(id,host,opt)
    local dns_query
    math.randomseed(os.time())
    local trans_id
    if id == nil then
        trans_id = string.char(math.random(1,255),math.random(1,255))
    else
        trans_id = id
    end
    local flags
    if not opt then
        flags = string.char(0x01,0x00)
    else
        flags = string.char(0x01,0x20)
    end
    local questions = string.char(0x00,0x01)
    local answer_rrs = string.char(0x00,0x00)
    local authority_rrs = string.char(0x00,0x00)
    if not opt then
        additional_rrs = string.char(0x00,0x00)
    else
        additional_rrs = string.char(0x00,0x01)
    end
    local queries_name,queries_type
    if host ~= nil then
        queries_name = get_queries_name(host)
        queries_type = string.char(0x00,0x01) --type A
    else
        queries_name = string.char(0x00)
        queries_type = string.char(0x00,0x02) --type NS
    end
    local queries_class = string.char(0x00,0x01) --class IN
    dns_query = trans_id .. flags .. questions .. answer_rrs .. authority_rrs .. additional_rrs .. queries_name .. queries_type .. queries_class
    return dns_query
end
function set_dns_additional_head()
    local additional_head
    --additional head
    local additional_name = string.char(0x00)
    local additional_type = string.char(0x00,0x29)
    local additional_udp_payload_size = string.char(0x10,0x00)
    local additional_higher_bits_in_extended_rcode = string.char(0x00)
    local additional_edns0_version = string.char(0x00)
    local additional_z = string.char(0x00,0x00)
    additional_head = additional_name .. additional_type .. additional_udp_payload_size .. additional_higher_bits_in_extended_rcode ..
            additional_edns0_version .. additional_z
    return additional_head
end
function set_dns_additional_option_csubnet(subnet)
    local additional_option_csubnet
    --additional option csubnet
    local additional_option_csubnet_code = string.char(0x00,0x08)
    local additional_option_csubnet_length
    local client_subnet, mask = get_host_address_mask(subnet)
    local additional_option_csubnet_family = string.char(0x00,0x01)
    local additional_option_csubnet_source_netmask = string.char(mask)
    local additional_option_csubnet_scope_netmask = string.char(0x00)
    local additional_option_csubnet_client_subnet = client_subnet
    additional_option_csubnet_length = string.len(additional_option_csubnet_family ..
            additional_option_csubnet_source_netmask .. additional_option_csubnet_scope_netmask .. additional_option_csubnet_client_subnet)
    if additional_option_csubnet_length <= 255 then additional_option_csubnet_length = string.char(0x00,additional_option_csubnet_length) end
    additional_option_csubnet = additional_option_csubnet_code .. additional_option_csubnet_length .. additional_option_csubnet_family ..
            additional_option_csubnet_source_netmask .. additional_option_csubnet_scope_netmask .. additional_option_csubnet_client_subnet
    return additional_option_csubnet
end
function set_dns_additional_option_cookie()
    local additional_option_cookie
    --additional option cookie
    local additional_option_cookie_code = string.char(0x00,0x0a)
    local additional_option_cookie_length = string.char(0x00,0x08)
    local additional_option_cookie_data = string.char(math.random(1,255),math.random(1,255),math.random(1,255),math.random(1,255),
            math.random(1,255),math.random(1,255),math.random(1,255),math.random(1,255))
    additional_option_cookie = additional_option_cookie_code .. additional_option_cookie_length .. additional_option_cookie_data
    return additional_option_cookie
end
function set_dns_additional_all_with_csubnet(dns_query,subnet)
    local additional_all,additional_head,additional_option_csubnet,additional_option_cookie
    --additional head
    additional_head = set_dns_additional_head()
    --additional option csubnet
    additional_option_csubnet = set_dns_additional_option_csubnet(subnet)
    --additional option cookie
    additional_option_cookie = set_dns_additional_option_cookie()
    --additional all
    local additional_data_length = string.len(additional_option_csubnet .. additional_option_cookie)
    if additional_data_length <= 255 then additional_data_length = string.char(0x00,additional_data_length) end
    additional_all = additional_head .. additional_data_length .. additional_option_csubnet .. additional_option_cookie
    return dns_query .. additional_all
end
function set_dns_additional_all_without_csubnet(dns_query)
    local additional_all,additional_head,additional_option_cookie
    --additional head
    additional_head = set_dns_additional_head()
    --additional option cookie
    additional_option_cookie = set_dns_additional_option_cookie()
    --additional all
    local additional_data_length = string.len(additional_option_cookie)
    if additional_data_length <= 255 then additional_data_length = string.char(0x00,additional_data_length) end
    additional_all = additional_head .. additional_data_length .. additional_option_cookie
    return dns_query .. additional_all
end
function set_dns_query_tcp(dns_query)
    return string.char(0x00,string.len(dns_query)) .. dns_query
end
function get_dns_resolver(host,server,port,timeout,tcp,opt,subnet)
    if host == nil then return nil end
    if string.find(host, "%d+%.%d+%.%d+%.%d") ~= nil then return host end  --ip v4 address
    if string.find(host, "::") ~= nil then return host end --ip v6 address
    local dns,data,client,err
    if tcp == "tcp" then
        client,err = lsocket.connect("tcp",server,port)
    elseif tcp == "udp" then
        client,err = lsocket.connect("udp",server,port)
    else return nil
    end
    if not client then
        print("error: "..err)
        return nil
    end
    if host == "" then
        data = set_dns_query(nil,nil,true)
        data = set_dns_additional_all_without_csubnet(data)
    else
        if not opt then
            data = set_dns_query(nil,host,false)
        else
            data = set_dns_query(nil,host,true)
            if subnet ~= nil then
                data = set_dns_additional_all_with_csubnet(data,subnet)
            end
        end
    end
    if tcp == "tcp" then
        data = set_dns_query_tcp(data)
    end
    lsocket.select(nil,{client})
    ok, err = client:send(data)
    if not ok then print("error: "..err) end
    lsocket.select({client})
    local response_message
    if tcp == "tcp" then
        local response_tcp_length, err = client:recv(2)
        response_message = client:recv(string.byte(response_tcp_length,1)*255+string.byte(response_tcp_length,2))
    else
        response_message = client:recv()
    end
    if(response_message) then
        local response_trans_id = string.sub(response_message,1,2)
        local response_flags =  string.sub(response_message,3,4)
        local response_questions = string.sub(response_message,5,6)
        local response_answers_rrs = string.sub(response_message,7,8)
        local response_authority_rrs = string.sub(response_message,9,10)
        local response_additional_rrs = string.sub(response_message,11,12)
        local response_trans_id = string.byte(string.sub(response_message,1,2))
        if response_flags == string.char(0x81,0x80) then
            local count_number = 12
            for i = 1,string.byte(response_questions,1)*255+string.byte(response_questions,2) do
                count_number = count_number + #get_queries_name(host) + 4
            end
            address_table = {}
            for i = 1,string.byte(response_answers_rrs,1)*255+string.byte(response_answers_rrs,2) do
                local answer_name = string.sub(response_message,count_number+1,count_number+2)  --"0xc0 0x0c"
                local answer_type = string.sub(response_message,count_number+3,count_number+4)  --"type A"
                local answer_class = string.sub(response_message,count_number+5,count_number+6)  --"Class IN"
                local answer_ttl = string.sub(response_message,count_number+7,count_number+10)  --"Time to live"
                local answer_length = string.sub(response_message,count_number+11,count_number+12)  --"Date length"
                answer_length = string.byte(answer_length,1)*255+string.byte(answer_length,2)
                local answer_address = string.sub(response_message,count_number+13,count_number+13+answer_length-1)  --"address"
                if answer_type == string.char(0x00,0x01) then
                    address = string.format("%s.%s.%s.%s",string.byte(answer_address,1),string.byte(answer_address,2),string.byte(answer_address,3),string.byte(answer_address,4))
                    --return address --return the first address
                    table.insert(address_table,address)
                end
                count_number = count_number + string.len(answer_name .. answer_type .. answer_class .. answer_ttl .. 0x00 .. 0x00 .. answer_address)
            end
            return address_table
        else
            return nil
        end
    end
    client:close()
    return dns
end
