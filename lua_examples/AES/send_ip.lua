print('send_ip.lua started')
local iv, cipher =...
local ip = wifi.sta.getip()
local chipid = node.chipid()

conn = nil
conn=net.createConnection(net.TCP, 0) 
local content = ("chip_id="..chipid.."&ip_address="..ip.."&data="..cipher.."&value="..iv)
print (content)
local length = string.len(content)
-- show the retrieved web page
conn:on("receive", function(conn, payload) 
                       success = true
                       print(payload) 
                       end) 

-- when connected, request page (send parameters to a script)
conn:on("connection", function(conn, payload) 
                       print('\nConnected') 
                       conn:send("POST /api/devices/update_ip_secure"
                        .." HTTP/1.1\r\n" 
                        .."Host: 123.123.1.2\r\n" 
                        .."Content-Type: application/x-www-form-urlencoded\r\n"
                        .."Content-Length: "..length.."\r\n\r\n"
                        ..content)
                       end)
-- when disconnected, let it be known
conn:on("disconnection", function(conn, payload) print('\nDisconnected') end)
                                             
conn:connect(80,"123.123.1.2")