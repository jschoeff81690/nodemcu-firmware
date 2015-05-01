local plaintext = "10455290-detected"
print ("plain:"..plaintext)
local len =  string.len(plaintext);
if(len%16 ~= 0) then
	for i=0,(15-len%16),1 do
		plaintext = plaintext.." "
	end
end
print ("padded:"..plaintext)
local iv = aes.generate_iv()
local key = "12345678912345678912345678901234"
print("iv: "..iv)
--setup keys
aes.init(key, iv, aes.AES_256)
aes.encrypt(plaintext)

--print encrypted text
file.open("cipher.lua","r")
local cipher = file.read()
print("cipher: "..cipher)
file.close()


--setup decryption
aes.init_decrypt(key, iv, aes.AES_256);
local a,b=aes.decrypt("cipher.lua");
print(a)
print(b)
--print decrypted text
file.open("output.lua","r")
local plain = file.read()
print("decrypted: "..plain)
file.close()
