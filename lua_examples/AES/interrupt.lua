local pin = 5    --> GPIO14
local last_t = tmr.now()
local encrypt = loadfile("encrypt.lua")
function onChange ()
	local t = tmr.now()
	if (t-last_t)/100 > 30000 then
		local iv, cipher = encrypt(key, node.chipid())
		assert(loadfile("update_meta.lc"))("Motion", iv, cipher)
		last_t = t
	end
end

gpio.mode(4, gpio.OUTPUT)
gpio.write(4,gpio.HIGH)
gpio.mode(pin, gpio.INT)
gpio.trig(pin, 'down', onChange)