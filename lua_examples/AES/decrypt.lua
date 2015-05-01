local key, iv, cipher =... --passed in as parameters
print("Begin Decryption");
print ("Cipher:"..cipher)
print ("iv:"..iv)
print ("key:"..key)
--write cipher to file
file.open("cipher.lua", "w+")
file.write(cipher)
file.close()

--setup keys
aes.init_decrypt(key, iv, aes.AES_256)
aes.decrypt("cipher.lua")

--print decrypted text
file.open("output.lua","r")
local plain = file.read()
print("decrypted: "..plain)
file.close()

return plain