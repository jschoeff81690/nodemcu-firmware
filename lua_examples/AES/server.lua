local secret_key=...
lighton=1 
pin=5
gpio.write(pin,gpio.HIGH)
srv=net.createServer(net.TCP) 
srv:listen(80,function(conn) 
  conn:on("receive",function(conn,payload)
  local indexStart, indexEnd = string.find(payload,"action=");
  local action, cipher, iv
  if indexStart ~= nil then 
    action = string.sub(payload,8)
    print(action)
    for word in string.gmatch(payload, '([^&]+)') do
    local i=0, key, value
    for pair in string.gmatch(word, '([^=]+)') do
      if i==0 then
      key = pair
      else
      value = pair
      end
      i = i+1
    end
    if (key == "action") then
      action = value
    elseif(key == "data") then
      cipher= value
    elseif(key == "val") then
      iv = value
    end
    end
  end
  --action cipher and key should be set
  if(cipher ~= nil and iv ~= nil) then 
    local decrypt = loadfile("decrypt.lc")
    local plaintext = decrypt(secret_key, iv, cipher);
    plaintext = string.gsub(plaintext, "%s+", "") -- trim the whitspace
    if("10455196" ~= plaintext) then 
      print("mismatch") 
    else
      if(action =="on") then
        lighton=1 
        gpio.write(pin,gpio.HIGH)
        print("on")
      else
        lighton=0
        print("off")
        gpio.write(pin,gpio.LOW)
      end
    end
    --do action stuff
  end
  end)
  conn:send('HTTP/1.1 200 OK\n\n')
  conn:send('<!DOCTYPE HTML>\n')
  conn:send('<html>\n')
  conn:send('<head><meta  content="text/html; charset=utf-8">\n')
  conn:send('<title>ESP8266</title></head>\n')
  conn:send('<body><h1>Sample GPIO output control</h1>\n')
  conn:on("sent",function(conn) conn:close() end)
end)
