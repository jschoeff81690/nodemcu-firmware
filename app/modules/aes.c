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


void ICACHE_FLASH_ATTR 
aes_int_to_char(const uint8_t *in, char *out, size_t length) {
	int i =0;
	for (i=0; i<length;i++){
		out[i] = (char)(0xFF & in[i]);
	}
}
void ICACHE_FLASH_ATTR 
aes_char_to_int(const char *in, uint8_t *out, size_t length) {
	int i =0;
	for (i=0; i<length;i++){
		out[i] = (int)(in[i]);
	}
}
static volatile int input_fd = FS_OPEN_OK - 1;
static AES_CTX aes_ctx;

static int aes_init( lua_State* L) {
 	os_memset( &aes_ctx, 0, sizeof( AES_CTX ) );
    uint8_t *key, *iv;	
	size_t k_len, iv_len;

	//get input from lua
	const unsigned char *key_tmp = luaL_checklstring(L,1, &k_len);
	const unsigned char *iv_tmp = luaL_checklstring(L,2, &iv_len);
	
	key = (uint8_t *)key_tmp;
	iv = (uint8_t *)iv_tmp;
	
	AES_set_key(&aes_ctx, key, iv, AES_MODE_256);
	
	return 1;
}

static int aes_encrypt( lua_State* L ) {
	int i;
	uint8_t *out_data, *in_data;
	size_t in_len;
	char result[32];
	const char *in_data_tmp = luaL_checklstring(L, 1, &in_len);
	
	in_data = (uint8_t *)in_data_tmp;

	//encrypt
	AES_cbc_encrypt(&aes_ctx, in_data, 
		out_data, in_len);
	
	result = (char *)out_data;
	lua_pushstring(L, result);
	return 1;
}


static int aes_encrypt( lua_State* L ) {
	int i;
	uint8_t *out_data, *in_data;
	size_t in_len;
	char result[32];
	const char *in_data_tmp = luaL_checklstring(L, 1, &in_len);
	
	in_data = (uint8_t *)in_data_tmp;

	//encrypt
	AES_cbc_encrypt(&aes_ctx, in_data, 
		out_data, in_len);
	
	result = (char *)out_data;
	lua_pushstring(L, result);
	luaL_Buffer b;
	luaL_buffinit(L, &b);
	/*char *p = luaL_prepbuffer(&b);*/
	uint8_t *list = luaL_prepbuffer(&b);
	luaL_addsize(&b, i);
	luaL_pushresult(&b); 


	return 1;
}


static int aes_decrypt( lua_State* L ) {
	int i;
	char *result;
	uint8_t *in_data, *out_data;
	size_t in_len;	
	const char *in_data_tmp = luaL_checklstring(L,1,&in_len);
	
	in_data = (uint8_t *)in_data_tmp;
	//cbc decrypt
	AES_cbc_decrypt(&aes_ctx, in_data, out_data, in_len);
	
	result = (char *)out_data;
	lua_pushstring(L, result);
	return 1;
}


// Lua: open(filename, mode)
static int aes_file_open( lua_State* L ) {
  size_t len;
  if((FS_OPEN_OK - 1)!=input_fd){
    fs_close(input_fd);
    input_fd = FS_OPEN_OK - 1;
  }

  const char *fname = luaL_checklstring( L, 1, &len );
  if( len > FS_NAME_MAX_LENGTH )
    return luaL_error(L, "filename too long");
  const char *mode = luaL_optstring(L, 2, "r");

  input_fd = fs_open(fname, fs_mode2flag(mode));

  if(input_fd < FS_OPEN_OK){
    input_fd = FS_OPEN_OK - 1;
    lua_pushnil(L);
  } else {
    lua_pushboolean(L, 1);
  }
  return 1; 
}

// Lua: close()
static int aes_file_close( lua_State* L ) {
  if((FS_OPEN_OK - 1)!=input_fd){
    fs_close(input_fd);
    input_fd = FS_OPEN_OK - 1;
  }
  return 0;  
}
static int aes_read2( lua_State* L ) {
	int i =0;
	size_t len;
	const unsigned char *num = luaL_checklstring(L, 1, &len);
	uint8_t *data = (uint8_t *)num;
	char *result = (char *)data;
	lua_pushstring(L, result);
	return 1;
}

static int aes_read3( lua_State* L ) {
	int i =0;
	size_t len;
	const unsigned char *num = luaL_checklstring(L, 1, &len);
	uint8_t *data = (uint8_t *)num;
		
	for (i=0; i<len;i++){
		lua_pushnumber(L,data[i]);
	}
	return len;
}
static int aes_string( lua_State *L) {
	size_t len;
	const char *num = luaL_checklstring(L, 1, &len);
	
	lua_pushnumber(L,len);
	lua_pushstring(L,num);
	return 2;
}

static int aes_file_read(lua_State* L) {
 	int n;
	int16_t end_char;
	n = LUAL_BUFFERSIZE;
	end_char = EOF;
	if(n< 0 || n>LUAL_BUFFERSIZE) 
			n = LUAL_BUFFERSIZE;
	if(end_char < 0 || end_char >255)
		end_char = EOF;
	int ec = (int)end_char;

	luaL_Buffer b;
	if((FS_OPEN_OK - 1)==input_fd)
		return luaL_error(L, "open a file first");

	luaL_buffinit(L, &b);
	/*char *p = luaL_prepbuffer(&b);*/
	uint8_t *list = luaL_prepbuffer(&b);
	
	int c = EOF;
	int i = 0;

	do{
		c = fs_getc(input_fd);
		if(c==EOF){
			break;
		}
		/*p[i++] = (char)(0xFF & c);*/
		list[i++] = (0xFF & c);
	}
	while((c!=EOF) && (c!=ec) && (i<n) );

	//if(i>0 && p[i-1] == '\n')
#if 0
	if(i>0 && list[i-1] == '\n')
	i--;    /* do not include `eol' */
#endif

	if(i==0){
		luaL_pushresult(&b);  /* close buffer */
		return (lua_objlen(L, -1) > 0);  /* check whether read something */
	}

	luaL_addsize(&b, i);
	luaL_pushresult(&b);  /* close buffer */
	return 1;  /* read at least an `eol' */ 
}

static int aes_print( lua_State* L ) {
	lua_pushliteral(L,"-----------------   AES DEBUG   ----------------\n");
	if (&aes_ctx == NULL){
		lua_pushstring(L,"context is null");
		return;
	}
	lua_pushliteral(L,"-----------------   AES DEBUG   ----------------\n");
	lua_pushliteral(L,"Size: ");
	return 1;
}

#define MIN_OPT_LEVEL 2
#include "lrodefs.h"
const LUA_REG_TYPE aes_map[] =
{
		  { LSTRKEY( "init" ), LFUNCVAL( aes_init)},
		  /*{ LSTRKEY( "print" ), LFUNCVAL( aes_print)},*/
		  { LSTRKEY( "rstring" ), LFUNCVAL( aes_string)},
		  { LSTRKEY( "read3" ), LFUNCVAL( aes_read3)},
		  { LSTRKEY( "read2" ), LFUNCVAL( aes_read2)},
		  { LSTRKEY( "fread" ), LFUNCVAL( aes_file_read)},
		  { LSTRKEY( "fopen" ), LFUNCVAL( aes_file_open)},
		  { LSTRKEY( "fclose" ), LFUNCVAL( aes_file_close)},
		  { LSTRKEY( "encrypt" ), LFUNCVAL( aes_encrypt)},
		  { LSTRKEY( "decrypt" ), LFUNCVAL( aes_decrypt)},
  { LNILKEY, LNILVAL}
};

LUALIB_API int luaopen_aes(lua_State *L) {
  // TODO: Make sure that the GPIO system is initialized
  LREGISTER(L, "aes", aes_map);
  return 1;
}
