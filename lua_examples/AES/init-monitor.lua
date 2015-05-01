print(node.chipid())
print("set up wifi mode")
local c = loadfile("config.lua")
local encrypt = loadfile("encrypt.lua")
if(c == nil)then
    print("Missing config")
    --assert red LED
else
    local ap, pass, server_ip, key = c()

    wifi.setmode(wifi.STATION)
    wifi.sta.config(ap, pass)
    wifi.sta.connect()


    tmr.alarm(1, 1000, 1, function() 
        if wifi.sta.getip()== nil then 
            print("IP unavailable, "..wifi.sta.status()) 
        else 
            tmr.stop(1)
            local ip=wifi.sta.getip()
            print("Configuration done, IP is "..ip)
            local iv, ip_cipher = encrypt(key, node.chipid())
            encrypt = nil
            assert(loadfile("send_ip.lua"))(iv, ip_cipher)
            assert(loadfile("server.lua"))(key)
            -- dofile("timer.lc") -- uses update_meta.lua
        end 
     end)
end
