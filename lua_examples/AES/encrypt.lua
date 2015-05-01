local key, plaintext =... --passed in as parameter
print("Begin Encryption");
print ("plain:"..plaintext)

--padded for plaintext, basic spaces
local len =  string.len(plaintext);
if(len%16 ~= 0) then
	for i=0,(15-len%16),1 do
		plaintext = plaintext.." "
	end
end
print ("padded:"..plaintext)


local iv = aes.generate_iv()
print("iv: "..iv)

--setup keys
aes.init(key, iv, aes.AES_256)
aes.encrypt(plaintext)

--print encrypted text
file.open("cipher.lua","r")
local cipher = file.read()
file.close()

return iv, cipher