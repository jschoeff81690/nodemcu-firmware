#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "platform.h"
#include "auxmods.h"
#include "lrotable.h"

#include "c_types.h"
#include "flash_fs.h"
#include "c_string.h"
#include "ssl/ssl_crypto.h"

static volatile int input_fd = FS_OPEN_OK - 1;
static volatile int output_fd = FS_OPEN_OK - 1;
static AES_CTX aes_ctx;


/**
 * Takes Ascii input as Hex and returns array with correspong value
 * e.g. "03F2" -> 00000011 11110010
 * - returns hald size of input
 */
static int ICACHE_FLASH_ATTR 
aes_fread_hex( uint8_t *out, size_t *len) {

	int ec = (int)EOF;
	char s;
	uint8_t hi,lo;
	int c = EOF;
	int i = 0;

	if((FS_OPEN_OK - 1)==input_fd)
		return -1;
	
	do{
		//get upper nibble
		c = fs_getc(input_fd);
		if(c==EOF){
		  break;
		}
		s = (unsigned char)(0xFF & c);
		//convert the ascii char to int
		//if char is in range A-F
		if( s > 64 && s < 71 ) {
				hi = s-55; 
		}
		// if char is in range a-f
		else if( s > 96 && s < 103 ) {
				hi = s-87; 
		}
		//in range 0-9
		else if( s > 47 && s < 58 ) {
			hi = s-48;
		}
		
		c = fs_getc(input_fd);
		if(c==EOF){
			break;
		}
		s = (unsigned char)(0xFF & c);
		//convert the ascii char to int
		//if char is in range A-F
		if( s > 64 && s < 71 ) {
				lo = s-55; 
		}
		// if char is in range a-f
		else if( s > 96 && s < 103 ) {
				lo = s-87; 
		}
		//in range 0-9
		else if( s > 47 && s < 58 ) {
			lo = s-48;
		}
		//out =  hi concatenate lo
		out[i++] = (hi<<4) | lo;
	}while((c!=EOF) && (c!=ec) );
	*len = i;
	return 1;
}

/**
 * Close File
 */
static int ICACHE_FLASH_ATTR 
aes_fclose() {
	if((FS_OPEN_OK - 1) != input_fd){
		fs_close(input_fd);
		input_fd = FS_OPEN_OK - 1;
	}
	return 0; 
}

/**
 * Write a single line to file and end with "\n"
 */
static int ICACHE_FLASH_ATTR 
aes_fwrite_line(const char *s, size_t len) {
	if((FS_OPEN_OK - 1) == input_fd)
		return -1;
	size_t rl;
	rl = fs_write(input_fd, s, len);
	if(rl==len) {
		rl = fs_write(input_fd, "\n", 1);
		if(rl == 1)
			return 1;
		else
			return 0;
	}
	else
		return 0;
}
/*
 * Write text to file, no end appended
 */
static int ICACHE_FLASH_ATTR 
aes_fwrite(const char *s, size_t len) {
	if((FS_OPEN_OK - 1) == input_fd)
		return -1;
	size_t rl;
	rl = fs_write(input_fd, s, len);
	if(rl==len)
		return 1;
	else
		return 0;
}

/*
 * Open a File
 * Return:
 * -1 for filename error
 * 0 error opening file
 * 1 successfully opened file
 */
static int ICACHE_FLASH_ATTR 
aes_fopen(const char *fname, size_t len, const char *mode) {
	//make sure its not already open
	if((FS_OPEN_OK - 1) != input_fd){
		fs_close(input_fd);
		input_fd = FS_OPEN_OK - 1;
	}
	if( len > FS_NAME_MAX_LENGTH )
		return -1;
	
	input_fd = fs_open(fname, fs_mode2flag(mode));

	if(input_fd < FS_OPEN_OK){
		input_fd = FS_OPEN_OK - 1;
		return 0;
	} else {
		return 1;
	}
}
/**
 * Sets up AES context for encryption
 * Takes key as ascii string input, and the mode  (128,256)
 */
static int aes_init( lua_State* L) {
 	//initialize the ctx
	os_memset( &aes_ctx, 0, sizeof( AES_CTX ) );
    uint8_t *key;	
	size_t k_len, iv_len;
	AES_MODE mode;
	
	//set IV	
	uint8_t iv[AES_IV_SIZE];
	//generate random IV, (16bytes)
	get_random(AES_IV_SIZE, iv);
	//get input from lua
	const unsigned char *key_tmp = luaL_checklstring(L,1, &k_len);
	/*const unsigned char *iv_tmp = luaL_checklstring(L,2, &iv_len);*/
	int mode_num = lua_tointeger(L,3);

	if(mode_num)
		mode = AES_MODE_256;
	else
		mode = AES_MODE_128;

	key = (uint8_t *)key_tmp;
	/*iv = (uint8_t *)iv_tmp;*/
	
	//do key scheduling
	AES_set_key(&aes_ctx, key, iv, mode);

	//return nothing to lua
	return 0;
}

/**
 * Sets up AES context for decryption
 * takes string key as input and mode
 */
static int aes_init_decrypt( lua_State* L ) {
 	//initialize the ctx
	os_memset( &aes_ctx, 0, sizeof( AES_CTX ) );
    uint8_t *key, *iv;	
	size_t k_len, iv_len;
	AES_MODE mode;

	//get input from lua
	const unsigned char *key_tmp = luaL_checklstring(L,1, &k_len);
	const unsigned char *iv_tmp = luaL_checklstring(L,2, &iv_len);
	int mode_num = lua_tointeger(L,3);

	if(mode_num)
		mode = AES_MODE_256;
	else
		mode = AES_MODE_128;

	key = (uint8_t *)key_tmp;
	iv = (uint8_t *)iv_tmp;
	
	//do key scheduling
	AES_set_key(&aes_ctx, key, iv, mode);
//set keyschedule for decrypt
	AES_convert_key(&aes_ctx);
	
	return 0;
}
static int aes_encrypt( lua_State* L ) {
	uint8_t  *in_data;
	size_t in_len;
	int i =0,buffer_len;
	const char *fname = "cipher.lua";
	const char *fmode = "w+";
	int result = aes_fopen(fname, 10, fmode);
	char buffer[33];
	
	//make sure set keys has been called
	if (&aes_ctx == NULL){
		lua_pushliteral(L,"aes has not been init");
		return 1;
	}
	
	//check if open file for output
	if(result == -1) {
		lua_pushliteral(L,"Error filename too long");
		return 1;
	}
	else if(!result) {
		lua_pushliteral(L,"Error opening file.");
		return 1;
	}
	
	//get the input data from lua 
	const char *in_data_tmp = luaL_checklstring(L, 1, &in_len);
	uint8_t out_data[in_len*8];
	//convert input to 8bit int
	in_data = (uint8_t *)in_data_tmp;
	/*os_memcpy(in_data, in_data_tmp, in_len);*/
	
	//encrypt
	AES_cbc_encrypt(&aes_ctx, in_data, out_data, in_len*8);
	
	//output result to file
	int data_len = sizeof(out_data)/sizeof(out_data[0]);	
	
	//16*8 = 128 bits
	for(i=0; i < in_len; i++){
		os_sprintf(buffer, "%02X", out_data[i]);
		buffer_len = sizeof(buffer)/sizeof(buffer[0]);
		aes_fwrite(buffer, 2);
		WRITE_PERI_REG(0x60000914, 0x73);	
	}
	//add a null
	aes_fwrite("", 1);
	//file close
	aes_fclose();

	//return to lua
	lua_pushliteral(L,"Encrypted text output to cipher.lua.");
	return 1;
}
static int aes_decrypt( lua_State* L ) {
	int i, buffer_len;
	uint8_t in_data[256];//max of 256 bytes to decrypt
	size_t in_len;	
	const char *fname = "output.lua";
	const char *fmode = "w+";
	
	//get filename for cipher
	const char *cipher_name = luaL_checklstring(L, 1, &in_len);
	
	//open cipher text
	int result = aes_fopen(cipher_name, in_len, "r");
	char buffer[33];
	
	//make sure set keys has been called
	if (&aes_ctx == NULL){
		lua_pushliteral(L,"aes has not been init");
		return 1;
	}
	
	//check if open file for output
	if(result == -1) {
		lua_pushliteral(L,"Error cipher filename too long");
		return 1;
	}
	else if(!result) {
		lua_pushliteral(L,"Error opening cipher file.");
		return 1;
	}
	//read the cipher text into in_data
	aes_fread_hex(in_data, &in_len);
	//close cipher fle
	aes_fclose();
	//create outdata buffer
	uint8_t out_data[in_len];	
	
	//const char *in_data_tmp = luaL_checklstring(L,1,&in_len);
	
	//in_data = (uint8_t *)in_data_tmp;
	
	//cbc decrypt
	AES_cbc_decrypt(&aes_ctx, in_data, out_data, in_len);
	

	//begin writing plaintext to file
	
	//open output text
	result = aes_fopen(fname, 10, fmode);
	

	//check if open file for output
	if(result == -1) {
		lua_pushliteral(L,"Error cipher filename too long");
		return 1;
	}
	else if(!result) {
		lua_pushliteral(L,"Error opening cipher file.");
		return 1;
	}

	//16*8 = 128 bits
	for(i=0; i < 16; i++){
		os_sprintf(buffer, "%c", (char)out_data[i]);
		buffer_len = sizeof(buffer)/sizeof(buffer[0]);
		aes_fwrite(buffer, 1);
		WRITE_PERI_REG(0x60000914, 0x73);	
	}
	//add a null
	aes_fwrite("", 1);
	//file close
	aes_fclose();
	/*result = (char *)out_data;*/
	/*lua_pushstring(L, result);*/

	lua_pushliteral(L,"Plaintext stored in output.lua");
	return 1;
}

static int aes_dump( lua_State* L ) {
	int ks_len= 28;
	int iv_len= AES_IV_SIZE;
	int i =0,buffer_len;
	const char *fname = "output.lua";
	const char *fmode = "w+";
	int result = aes_fopen(fname, 10, fmode);
	char buffer[33];
	//make sure set keys has been called
	if (&aes_ctx == NULL){
		lua_pushliteral(L,"context is null");
		return 1;
	}
	
	//attempt to open file for output
	if(result == -1) {
		lua_pushliteral(L,"filename too long");
		return 1;
	}
	else if(!result) {
		lua_pushliteral(L,"Error opening file.");
		return 1;
	}
	
	aes_fwrite_line("-----------------   AES DEBUG   ----------------",38);
	
	aes_fwrite("Rounds: ", 8);
	os_sprintf(buffer, "%d", aes_ctx.rounds);
	buffer_len = sizeof(buffer)/sizeof(buffer[0]);
	aes_fwrite_line(buffer, buffer_len);
	
	aes_fwrite("key size: ", 10);
	os_sprintf(buffer, "%d", aes_ctx.key_size);
	buffer_len = sizeof(buffer)/sizeof(buffer[0]);
	aes_fwrite_line(buffer, buffer_len);
	
	aes_fwrite("key space: ", 11);
	
	for(i=0; i<ks_len;i++){
		os_sprintf(buffer, "%X", aes_ctx.ks[i]);
		buffer_len = sizeof(buffer)/sizeof(buffer[0]);
		aes_fwrite_line(buffer, buffer_len);
		WRITE_PERI_REG(0x60000914, 0x73);	
	}


	aes_fwrite("IV: ", 4);
	
	for(i=0; i< AES_IV_SIZE;i++){
		os_sprintf(buffer, "%X", aes_ctx.iv[i]);
		buffer_len = sizeof(buffer)/sizeof(buffer[0]);
		aes_fwrite_line(buffer, buffer_len);
		WRITE_PERI_REG(0x60000914, 0x73);	
	}

	aes_fclose();	
	lua_pushliteral(L, "Dump AES ctx to output.lua");
	return 1;
}

static int aes_rng( lua_State* L ) {
	uint8_t data[AES_IV_SIZE];
	get_random(AES_IV_SIZE,data);
	
	lua_pushstring(L, (char *)data);
	return 1;
}
#define MIN_OPT_LEVEL 2
#include "lrodefs.h"
const LUA_REG_TYPE aes_map[] =
{
		  { LSTRKEY( "init" ), LFUNCVAL( aes_init)},
		  { LSTRKEY( "init_decrypt" ), LFUNCVAL( aes_init_decrypt)},
		  { LSTRKEY( "dump" ), LFUNCVAL( aes_dump)},
		  { LSTRKEY( "new_iv" ), LFUNCVAL( aes_rng )},
		  { LSTRKEY( "encrypt" ), LFUNCVAL( aes_encrypt)},
		  { LSTRKEY( "decrypt" ), LFUNCVAL( aes_decrypt)},
		  { LSTRKEY( "AES_256" ), LNUMVAL( 1 )},
		  { LSTRKEY( "AES_128" ), LNUMVAL( 0 )},
  { LNILKEY, LNILVAL}
};

LUALIB_API int luaopen_aes(lua_State *L) {
  // TODO: Make sure that the GPIO system is initialized
  LREGISTER(L, "aes", aes_map);
  return 1;
}
