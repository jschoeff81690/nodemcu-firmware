-- tested on NodeMCU 0.9.5 build 20141222...20150108
-- sends connection time and heap size to http://benlo.com/esp8266/test.php

print('update_meta.lua started')
local value, iv, cipher=...

print("value: "..value)


conn = nil
conn=net.createConnection(net.TCP, 0) 
local content = ("chip_id="..node.chipid().."&value="..value.."&key=state".."&data="..cipher.."&val="..iv)
print (content)
local length = string.len(content)
print (length)
-- show the retrieved web page
conn:on("receive", function(conn, payload) 
                       success = true
                       print(payload) 
                       end) 

-- when connected, request page (send parameters to a script)
conn:on("connection", function(conn, payload) 
                       print('\nConnected') 
                       conn:send("POST /api/devices/update_meta_secure"
                        .." HTTP/1.1\r\n" 
                        .."Host: 123.123.1.2\r\n" 
                        .."Content-Type: application/x-www-form-urlencoded\r\n"
                        .."Content-Length: "..length.."\r\n\r\n"
                        ..content)
                       end)
-- when disconnected, let it be known
conn:on("disconnection", function(conn, payload) print('\nDisconnected') end)
                                             
conn:connect(80,"123.123.1.2")
