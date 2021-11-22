
/* <DESC>
 *
 * </DESC>
 */
#include <curl/curl.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include "cJSON.h"
//#include "b64.h"
//#include "bcrypt.h"
#include "ow-crypt.h"
//#define NOT_INCULE_FUNC_DECLARATION
#include "curlhttps.h"
#include "debug.h"
#include "mqtt_async_wrapper.h"

#define SKIP_PEER_VERIFICATION
#define SKIP_HOSTNAME_VERIFICATION
#define BCRYPT_HASHSIZE (64)
#define BLOCK_SIZE (16)
gateway_profile_t g_profile={0};
static char s_recvbuf[2048];
static int s_current = 0;
static size_t write_data_buf(void *ptr, size_t size, size_t nmemb, void *stream) {
  int num = size * nmemb;
  int i = 0;
  char *pIndex = (char *)ptr;
  for (i = 0; i < num; i++) {
    if (s_current + i >= 2048)
      break;

    s_recvbuf[s_current + i] = *(pIndex + i);
  }
  s_current += num;
  // size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return s_current;
}
static size_t write_data_file(void *ptr, size_t size, size_t nmemb, void *stream) {
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}
int http_get_file(uint8 *url,uint8 *file_name) {

  CURL *curl;
  CURLcode res =-1;
  long int resp_code = 0; 
  int curl_time = 0; 
  FILE* p_file = fopen(file_name, "wb" );
  if(p_file==NULL){
    debug_err_l5("open %s fail\n",file_name);
    return res;
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600);//设置超时时间 //fxy 0822

#ifdef SKIP_PEER_VERIFICATION
    /*
     * If you want to connect to a site who isn't using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the CURLOPT_CAPATH option might come handy for
     * you.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
    /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)p_file);//设置写数据
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data_file); //设置回调函数
    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if (res != CURLE_OK){
      // fprintf(stderr, "curl_easy_perform() failed: %s\n",
      //         curl_easy_strerror(res));
      debug_err_l5("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));       
    }
    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE , &resp_code);  
    if(CURLE_OK==res) 
       debug_info_l5("curl_easy_getinfo() resp_code: %d\n",resp_code);   
    // res = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME , &curl_time);  
    // if(CURLE_OK==res) 
    //    debug("curl_easy_getinfo() curl_time: %d\n",curl_time);         
    /* always cleanup */
    curl_easy_cleanup(curl);
  }else{
        debug_err_l5("curl_easy_init() failed\n");
  }

  curl_global_cleanup();
  if(p_file!=NULL){
    fclose(p_file);
    debug_info_l5("close %s\n",file_name);

  }
  return res; //fxy 0822
}


int http_post(char *url, char *body) {
  CURL *curl;
  CURLcode res = -1;
  struct curl_slist *headers = NULL;

  s_current = 0; //!!!!!!
  memset(s_recvbuf, 0, sizeof(s_recvbuf));
  
  headers =
      curl_slist_append(headers, "Content-Type:application/json;charset=UTF-8");  
  if(headers==NULL){
    return -1;
  }
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT_NUM);//设置超时时间 //fxy 0822
    /* Now specify the POST data */

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (strlen(body)));

#ifdef SKIP_PEER_VERIFICATION
    /*
     * If you want to connect to a site who isn't using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the CURLOPT_CAPATH option might come handy for
     * you.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
    /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data_buf); //设置回调函数
    // curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);//设置写数据

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if (res != CURLE_OK){
      // fprintf(stderr, "curl_easy_perform() failed: %s\n",
      //         curl_easy_strerror(res));
      debug_err_l5("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));        
    }    
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_slist_free_all(headers);
  curl_global_cleanup();

  return res; //fxy 0822
}
int http_get(char *url) {

  CURL *curl;
  CURLcode res =-1;
  long int resp_code = 0; 
  int curl_time = 0; 
  s_current = 0; //!!!!!
  memset(s_recvbuf, 0, sizeof(s_recvbuf));

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT_NUM);//设置超时时间 //fxy 0822

#ifdef SKIP_PEER_VERIFICATION
    /*
     * If you want to connect to a site who isn't using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the CURLOPT_CAPATH option might come handy for
     * you.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
    /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data_buf); //设置回调函数
    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if (res != CURLE_OK){
      // fprintf(stderr, "curl_easy_perform() failed: %s\n",
      //         curl_easy_strerror(res));
      debug_err_l5("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));       
    }
    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE , &resp_code);  
    if(CURLE_OK==res) 
       debug_info_l5("curl_easy_getinfo() resp_code: %d\n",resp_code);   
    // res = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME , &curl_time);  
    // if(CURLE_OK==res) 
    //    debug("curl_easy_getinfo() curl_time: %d\n",curl_time);         
    /* always cleanup */
    curl_easy_cleanup(curl);
  }else{
        debug_err_l5("curl_easy_init() failed\n");
  }

  curl_global_cleanup();

  return res; //fxy 0822
}


int test_aes_b64(void) {
  int i = 0;
  int size = 0;
  unsigned char *p_user_name = "174dcbc5-0d2a-480d-b5b4-3b37be80",
                user_name[65] = {0}; // ok
  unsigned char *key = "1234567890123456";
  // char *user_name = "174dcbc5-0d2a-480d-b5b4-3b37be80";
  
  debug_info_l5("p_user_name:%s\n", p_user_name);
  char encrypt_user_name_out[65] = {0};
  char decrypt_user_name_out[65] = {0};
  // char *password = "178f8b18-c754-468f-84f1-eea999ef29be";
  char enc[128+1] = {0}, dec[128+1] = {0};
  strlcpy(user_name, p_user_name, sizeof(user_name));
  
  // PKCS7Padding(user_name,sizeof(user_name), 16);

  aes_cbc_encrypt(user_name, strlen(user_name), encrypt_user_name_out, key);

  base64_encode(encrypt_user_name_out, strlen(user_name), enc,sizeof(enc));

  size = base64_decode(enc, strlen(enc), dec);

  aes_cbc_decrypt(dec, size, key,
              decrypt_user_name_out); // 32 tbd computed %16=0!!!!!
  //de-padding filter (<16), then end with 0
  for (i = 0; i < size; i++) {
    if (decrypt_user_name_out[i] <= 16) {
      decrypt_user_name_out[i] = 0;
      break;
    }
  }

  debug_info_l5("decrypt_user_name_out:%s\n", decrypt_user_name_out);

  return 0;
}
//raw len <512-16
int aes_ecb_b64_encode(unsigned char *p_raw,int raw_len, unsigned char *p_enc,int enc_max_len,unsigned char *key) {
  int i = 0;
  int size = 0;
  unsigned char raw[512+1] = {0}; //store string
  char encrypt_user_name_out[512] = {0}; //store binary
  //unsigned char *key = "1234567890all_1234567890"; //24字节
  // char *user_name = "174dcbc5-0d2a-480d-b5b4-3b37be80";
  
  if(raw_len>512){
    debug_err_l5("aes_b64_encode raw_max_len %d \n",raw_len);
    return -1;
  }
  
  // char *password = "178f8b18-c754-468f-84f1-eea999ef29be";

  strlcpy(raw, p_raw, sizeof(raw));
  
  PKCS7Padding(raw,sizeof(raw),16);  
  //in_len should equal = raw after padding len; !!!
  aes_ecb_encrypt(raw, strlen(raw), key,strlen(key), encrypt_user_name_out);

  base64_encode(encrypt_user_name_out, strlen(raw), p_enc,enc_max_len);
  //debug_info_l5("decrypt_user_name_out:%s\n", decrypt_user_name_out);

  return 0;
}
int aes_ecb_b64_decode(unsigned char *p_enc,int enc_len, unsigned char *p_raw, unsigned char *key) {
  int i = 0;
  int size = 0;
  char dec[512] = {0}; //store binary
   // char *user_name = "174dcbc5-0d2a-480d-b5b4-3b37be80";
  
  if(enc_len>512+170){  //170=512/3
    debug_info_l5("aes_b64_decode enc_len %d \n",enc_len);
    return -1;
  }
  
  // char *password = "178f8b18-c754-468f-84f1-eea999ef29be";
   

  size = base64_decode(p_enc, strlen(p_enc), dec);
  debug_info_l5("base64_decode size %d \n",size);
  aes_ecb_decrypt(dec, size, key,strlen(key),
              p_raw); // 32 tbd computed %16=0!!!!!
  //de-padding filter (<16), then end with 0
  for (i = 0; i < size; i++) {
    if (p_raw[i] <= 16) {
      p_raw[i] = 0;
      break;
    }
  }


  //debug_info_l5("decrypt_user_name_out:%s\n", decrypt_user_name_out);

  return 0;
}

RSA *createRSA(unsigned char *key, int publi) {
  unsigned char key_with_header[2048+54] = {0};
  //unsigned char *begin ="-----BEGIN RSA PRIVATE KEY-----\n";
  //unsigned char *end ="-----END RSA PRIVATE KEY-----\n";
  unsigned char *begin = "-----BEGIN PRIVATE KEY-----\n";
  unsigned char *end = "\n-----END PRIVATE KEY-----";
  RSA *rsa = NULL;
  BIO *keybio;
#if 1
  strlcpy(key_with_header, begin, sizeof(key_with_header));
  strlcat(key_with_header , key, sizeof(key_with_header));
  strlcat(key_with_header, end, sizeof(key_with_header));
  debug_info_l5("key len %d \n", strlen(key));
  debug_info_l5("begin len %d \n", strlen(begin));
#else
#endif

  keybio = BIO_new_mem_buf(key_with_header, -1);
  if (keybio == NULL) {
    debug_err_l5("Failed to create key BIO\n");
    return 0;
  }
  if (publi) {
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
  } else {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
  }
  if (rsa == NULL) {
    debug_err_l5("Failed to create RSA\n");
  }
  return rsa;
}
#if 0
int rsa_sha1_private_sign(const unsigned char *in, unsigned char *key,
                          unsigned char *out, unsigned int *outlen) {
  unsigned char rsa_sign_out[1024]={0};
  unsigned char in_sha1[SHA_DIGEST_LENGTH]={0};  //sha1 len fix 20
  int rsa_sign_out_len = 0;
  int result = 0;
  RSA *rsa = NULL;
  // base64_decode(in, strlen(in),in_b64_dec);
  // debug_info_l5("%s\n", in_b64_dec);
  memset(in_sha1, 0, sizeof(in_sha1));
  SHA1(in, strlen(in), in_sha1);
  rsa = createRSA(key, 0);
  if(rsa ==NULL){  //fxy 0929 code review
    debug_info_l5("rsa_sha1_private_sign  createRSA error\n");
    return -1;  
  }
  //alink_printf_string_byhexs(in_sha1,SHA_DIGEST_LENGTH);
  //!!!SHA_DIGEST_LENGTH, binary not char
  result = RSA_sign(NID_sha1, in_sha1, SHA_DIGEST_LENGTH, rsa_sign_out,
                    &rsa_sign_out_len, rsa);
  // free(in_b64_dec);
  if (result != 1) {
    debug_info_l5("rsa_sha1_private_sign error\n");
    return -1;
  }
  //alink_printf_string_byhexs(rsa_sign_out,rsa_sign_out_len);
  *outlen = base64_encode(rsa_sign_out, rsa_sign_out_len, out,2048);
  //*outlen=strlen(out);
  debug_info_l5("rsa_sha1_private_sign out:%s\n", out);
  return 0;
  /*  rsa_key = RSA.importKey(base64.b64decode(self.encrypt_key))
          signer = Signature_pkcs1_v1_5.new(rsa_key)
          digest = SHA.new()
          digest.update(data.encode('UTF-8'))
          sign = signer.sign(digest)
          signature = base64.b64encode(sign)*/
}
#endif

int rsa_sha384_private_sign(const unsigned char *in, unsigned char *key,
                          unsigned char *out, unsigned int *outlen) {
  
  unsigned char rsa_sign_out[1024]={0};
  unsigned char rsa_sha384[SHA_DIGEST_LENGTH_384]={0};  //sha1 len fix 20
  int rsa_sign_out_len = 0;
  int result = 0;
  RSA *rsa = NULL;
  // base64_decode(in, strlen(in),in_b64_dec);
  // debug_info_l5("%s\n", in_b64_dec);
  memset(rsa_sha384, 0, sizeof(rsa_sha384));
  SHA384(in, strlen(in), rsa_sha384);
  rsa = createRSA(key, 0);
  if(rsa ==NULL){  //fxy 0929 code review
    debug_info_l5("rsa_sha384_private_sign  createRSA error\n");
    return -1;  
  }
  //alink_printf_string_byhexs(rsa_sha384,SHA_DIGEST_LENGTH);
  //!!!SHA_DIGEST_LENGTH, binary not char
  result = RSA_sign(NID_sha384, rsa_sha384, SHA_DIGEST_LENGTH_384, rsa_sign_out,
                    &rsa_sign_out_len, rsa);
  // free(in_b64_dec);
  if (result != 1) {
    debug_info_l5("rsa_sha384_private_sign error\n");
    return -1;
  }
  //alink_printf_string_byhexs(rsa_sign_out,rsa_sign_out_len);
  *outlen = base64_encode(rsa_sign_out, rsa_sign_out_len, out,2048);
  //*outlen=strlen(out);
  debug_info_l5("rsa_sha384_private_sign out:%s\n", out);
  return 0;
  /*  rsa_key = RSA.importKey(base64.b64decode(self.encrypt_key))
          signer = Signature_pkcs1_v1_5.new(rsa_key)
          digest = SHA.new()
          digest.update(data.encode('UTF-8'))
          sign = signer.sign(digest)
          signature = base64.b64encode(sign)*/
}

int get_mqtt_userpasswd_info(char *server, char *user_name, char *password,
                             char *hash_password) {
  int errcode = -1;
  int salt_len = 0;
  char encrypt_salt[64] = {0}, key[KEY_LEN] = {0}, salt[SALT_LEN] = {0};
  debug_info_l5("get_httpslogin&mqtt_userpasswd_info \n");
  errcode = auth_getsalt(server, user_name, encrypt_salt, key);
  if (errcode == 0) {
    get_decrypt_salt(encrypt_salt, key, salt,&salt_len);
    bcrypt_hashpw(password, salt, hash_password,BCRYPT_HASHSIZE);
  }
  return errcode;
}

int auth_getsalt_login(char *server, char *user_name, char *password,
                       Mqttsetting *mqttsetting) {

  char encrypt_salt[64] = {0}, key[KEY_LEN] = {0};

  int errcode = -1;
  Login_account account;
  memset(&account, 0, sizeof(account));

  // errcode=auth_active(server,user_name,password);
  // if(errcode==0){

  debug_info_l5("auth_getsalt_login\n");

  errcode = auth_getsalt(server, user_name, encrypt_salt, key);
  //}

  if (errcode == 0) {
    strlcpy(account.user_name, user_name, sizeof(account.user_name));
    strlcpy(account.password, password, sizeof(account.password));
    strlcpy(account.encrypt_salt, encrypt_salt, sizeof(account.encrypt_salt));
    strlcpy(account.key, key, sizeof(account.key));
    errcode = auth_login(server, &account, mqttsetting);
  }
  return errcode;
}
