#include "crypto_tools.h"

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

//print out the data as a hex string
void printHex(uint8_t* data, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%x", data[i]);
    }
    printf("\n");
}

//iv size is 12
//c1_ct size is iv size + msg_len + 32
//c1_tag size is 16
//c2 size is 32
int ccAEEnc(uint8_t* enc_key, uint8_t* msg, int msg_len, uint8_t* c1_ct, uint8_t* c1_tag, uint8_t* c2)
{
        //get 32 bytes of commitment randomness which will serve as an HMAC key
        uint8_t* hmac_key = malloc(32);
        if(1 != RAND_priv_bytes(hmac_key, 32))
        {
            printf("couldn't get randomness!\n");
            return 0;
        }

        //produce the commitment c2, which is an hmac of the message
        if(1 != hmac_it(hmac_key, msg, msg_len, c2))
        {
            printf("failed to HMAC\n");
            return 0;
        }

        //generate a random 12 byte IV and put it at the beginning of c1_ct
        if(1 != RAND_priv_bytes(c1_ct, 12))
        {
            printf("couldn't get randomness!\n");
            return 0;
        }

        uint8_t* iv = c1_ct; //for convenience

        //encrypt msg||hmac_key with hmac as the aad
        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;

        /* Create and initialise the context */
        if(!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        /* Initialise the encryption operation. */
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, enc_key, iv))
            handleErrors();

        /*
        * Provide any AAD data. This can be called zero or more times as
        * required
        */
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, c2, 32))
            handleErrors();

        /*
        * Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if(1 != EVP_EncryptUpdate(ctx, c1_ct+12, &len, msg, msg_len))
            handleErrors();
        ciphertext_len = len;

        if(1 != EVP_EncryptUpdate(ctx, c1_ct+12+len, &len, hmac_key, 32))
            handleErrors();
        ciphertext_len += len;

        /*
        * Finalise the encryption. Normally ciphertext bytes may be written at
        * this stage, but this does not occur in GCM mode
        */
        if(1 != EVP_EncryptFinal_ex(ctx, c1_ct+ 12 + ciphertext_len, &len))
            handleErrors();
        ciphertext_len += len;

        /* Get the tag */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, c1_tag))
            handleErrors();

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);
        free(hmac_key);

        return ciphertext_len+12;
}

int ccAEDec(uint8_t* enc_key, uint8_t* c1_ct, int c1_ct_len, uint8_t* c1_tag, uint8_t* c2, uint8_t* msg, uint8_t* fo)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    uint8_t* plaintext = malloc(c1_ct_len-12);//iv is in front of encrypted message
    uint8_t* iv = c1_ct; //for convenience

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, enc_key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, c2, 32))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, c1_ct+12, c1_ct_len-12))
        handleErrors();

    plaintext_len = len;
    plaintext_len -= 32;

    //copy msg and fo to their respective locations
    memcpy(msg, plaintext, plaintext_len);
    memcpy(fo, plaintext + plaintext_len, 32);

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, c1_tag))
        handleErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    if (len != 0 || c1_ct_len-12 != plaintext_len + 32){
        printf("something's wrong with lengths\n");
        handleErrors();
    }

    /* Clean up decryption */
    EVP_CIPHER_CTX_free(ctx);

    //next, check the MAC c2
    int commitment_verify = 0;
    commitment_verify = verify_hmac(fo, msg, plaintext_len, c2);

    free(plaintext);

    if(ret > 0 && commitment_verify == 1) {
        /* Success */
        //plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

int ccAEVerify(uint8_t* msg, int msg_len, uint8_t* c2, uint8_t* fo)
{
    return verify_hmac(fo, msg, msg_len, c2);
}

//initialize AES in CTR mode with IV 0 using seed as key, encrypt all zeros
int prg(uint8_t* seed, uint8_t* output, int output_len)
{
    uint8_t *zeros = (uint8_t*) malloc(output_len);
    memset(zeros, 0, output_len);

    int len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *seed_ctx;

    //create ctx for PRG
    if(!(seed_ctx = EVP_CIPHER_CTX_new()))
        handleErrors();


    if(1 != EVP_EncryptInit_ex(seed_ctx, EVP_aes_128_ctr(), NULL, seed, NULL))
        handleErrors();

    if(1 != EVP_EncryptUpdate(seed_ctx, output, &len, zeros, output_len))
        handleErrors();

    if(1 != EVP_EncryptFinal_ex(seed_ctx, output+len, &final_len))
        handleErrors();

    len += final_len;

    //These two messages should never be printed
    if(len > output_len)
    {
        printf("longer output than expected!\n");
        return 0;
    }
    else if(len < output_len)
    {
        printf("shorter output than expected!\n");
        return 0;
    }

    free(zeros);
    EVP_CIPHER_CTX_free(seed_ctx);

    return 1;
}

int hmac_it(uint8_t* key, const unsigned char *msg, size_t mlen, unsigned char *macRes)
{

    //set up EVP_PKEY for 256 bit (32 byte) hmac key
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, 32);
    if(!pkey)
    {
        goto err;
    }

    /* Returned to caller */
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    size_t req = 0;
    int rc;

    if(!msg || !mlen || !macRes || !pkey)
        return 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if (rc != 1) {
        printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
        goto err;
    }

    size_t macLen = req;
    rc = EVP_DigestSignFinal(ctx, macRes, &macLen);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
        goto err;
    }

    if(macLen != 32)
    {
        printf("MAC wrong length!\n");
        goto err;
    }

    result = 1;


 err:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

int verify_hmac(uint8_t* key, const unsigned char *msg, size_t mlen, const unsigned char *tag)
{
    size_t tagLen = 32;

    //set up EVP_PKEY for 256 bit (32 byte) hmac key
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, 32);
    if(!pkey)
    {
        goto err;
    }

    /* Returned to caller */
    int result = 0;
    EVP_MD_CTX* ctx = NULL;
    unsigned char buff[EVP_MAX_MD_SIZE];
    size_t size;
    int rc;

    if(!msg || !mlen || !tag || !pkey)
        return 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if (rc != 1) {
        printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    size = sizeof(buff);
    rc = EVP_DigestSignFinal(ctx, buff, &size);
    if (rc != 1) {
        printf("EVP_DigestSignFinal failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    result = (tagLen == size) && (CRYPTO_memcmp(tag, buff, size) == 0);
 err:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}


void digest_message(const unsigned char *message, size_t message_len, unsigned char *digest)
{
	EVP_MD_CTX *mdctx;

    unsigned int digest_len = 0;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len))
		handleErrors();

	EVP_MD_CTX_free(mdctx);

    if(digest_len != 32)
    {
        printf("sha256 output wrong length.\n");
        handleErrors();
    }
}
