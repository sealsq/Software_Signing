/* signature.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>

#include "wisekey_Tools.h"
#include "wisekey_Ines_API.h"
#include "wisekey_Crypto_Tools.h"

#include <wolfssl/wolfcrypt/port/wisekey/vaultic.h>
#include <wolfssl/wolfcrypt/port/wisekey/vaultic_tls.h>
#include <vaultic_tls_config.h>



#define ECC_KEY_SIZE 256
#define DER_FILE_BUFFER 256 /* max DER size */

#define PEM_TEMPLATE "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----"

static int load_file_to_buffer(const char *filename, byte **fileBuf, int *fileLen)
{
    int ret = 0;
    FILE *file = NULL;

    /* Open file */
    file = fopen(filename, "rb");
    if (file == NULL)
    {
        printf("File %s does not exist!\n", filename);
        ret = EXIT_FAILURE;
    }

    /* Determine length of file */
    fseek(file, 0, SEEK_END);
    *fileLen = (int)ftell(file);
    fseek(file, 0, SEEK_SET);
    printf("File %s is %d bytes\n", filename, *fileLen);

    /* Allocate buffer for image */
    *fileBuf = malloc(*fileLen);
    if (!*fileBuf)
    {
        ret = EXIT_FAILURE;
    }

    /* Load file into buffer */
    ret = (int)fread(*fileBuf, 1, *fileLen, file);
    if (ret != *fileLen)
    {
        printf("Error reading file! %d", ret);
        ret = EXIT_FAILURE;
    }

    if (file)
    {
        fclose(file);
    }

    return ret;
}

void hexdump(const void *buffer, word32 len, byte cols)
{
    word32 i;

    for (i = 0; i < len + ((len % cols) ? (cols - len % cols) : 0); i++)
    {
        /* print hex data */
        if (i < len)
        {
            printf("%02X ", ((byte *)buffer)[i] & 0xFF);
        }

        if (i % cols == (cols - 1))
        {
            printf("\n");
        }
    }
}

int load_Public_key_from_x509_pem_string(char *pem, ecc_key *eccKey)
{
    int ret = -1;
    FILE *file;
    word32 bytes = 0;
    word32 idx = 0;

    int pemSz = strlen(pem);

    DecodedCert cert;
    int derCertSz;
    byte derCert[2048];

    if((ret = wc_CertPemToDer(pem, pemSz, derCert, derCertSz, CERT_TYPE)) <= 0) {
        wkey_log(LOG_ERROR,"ERROR while converting pem to der %d, pem : %s",ret,pem);
        return -1;
    }

    /* initialize DecodedCert with DER cert */
    wc_InitDecodedCert(&cert, derCert, derCertSz, NULL);
    if ((ret = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL)) != 0)
    {
        wkey_log(LOG_ERROR,"wc_ParseCert failed.%d\n",ret);
        return ret;
    }

    if (ret = wc_EccPublicKeyDecode(cert.publicKey, &idx, eccKey, cert.pubKeySize) != 0)
       wkey_log(LOG_ERROR,"Error while wc_EccPublicKeyDecode Public key %d\n", ret);
        
    wc_FreeDecodedCert(&cert);

    return ret;
}

int VAULT_IC_SignatureVerify(byte *fileBuf, int fileLen, byte* sigBuf, word32 sigBufLen,ecc_key* key, int key_len)
{
    int ret;
    word32 hash_len, hash_enc_len;
    byte *hash_data;
    int err;
    byte signature[2*P256_BYTE_SZ];
    byte *r, *s;
    word32 r_len = P256_BYTE_SZ, s_len = P256_BYTE_SZ;
    byte pubKeyX[P256_BYTE_SZ];
    byte pubKeyY[P256_BYTE_SZ];
    word32 pubKeyX_len = sizeof(pubKeyX);
    word32 pubKeyY_len = sizeof(pubKeyY);

    if(vlt_tls_init() !=0) {
        wkey_log(LOG_ERROR,"ERROR: vic_tls_init error\n");
        return -1;
    }


    /* Validate signature len (1 to max is okay) */
    if ((int)sigBufLen > wc_SignatureGetSize(1, key, key_len)) {
        WOLFSSL_MSG("wc_SignatureVerify: Invalid sig type/len");
        return BAD_FUNC_ARG;
    }

    /* Validate hash size */
    ret = wc_HashGetDigestSize(6);
    if (ret < 0) {
        WOLFSSL_MSG("wc_SignatureVerify: Invalid hash type/len");
        return ret;
    }
    hash_enc_len = hash_len = (word32)ret;

    /* Allocate temporary buffer for hash data */
    hash_data = (byte*)XMALLOC(hash_enc_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash_data == NULL) {
        return MEMORY_E;
    }


    /* Perform hash of data */
    ret = wc_Hash(6, fileBuf, fileLen, hash_data, hash_len);   

    if (key == NULL || sigBuf == NULL || hash_data == NULL) {
        wkey_log(LOG_ERROR,"Bad Argument");
    }

    /* Extract Raw X and Y coordinates of the public key */
    if( (err = wc_ecc_export_public_raw(key, pubKeyX, &pubKeyX_len,
        pubKeyY, &pubKeyY_len)) !=0) {
         wkey_log(LOG_ERROR,"ERROR: wc_ecc_export_public_raw\n");
        return err;
    }
       
    /* Extract R and S from signature */
    XMEMSET(signature, 0, sizeof(signature));
    r = &signature[0];
    s = &signature[sizeof(signature)/2];
    err = wc_ecc_sig_to_rs(sigBuf, sigBufLen, r, &r_len, s, &s_len);

    if(err !=0) {
        wkey_log(LOG_ERROR,"ERROR: wc_ecc_sig_to_rs\n");
    }
        
    /* Verify signature with VaultIC */
    if (vlt_tls_verify_signature_P256(hash_data, hash_len, signature, pubKeyX, pubKeyY) != 0) {
        wkey_log(LOG_ERROR,"ERROR: vault_tls_verify_signature_P256\n");
        return WC_HW_E;
    }
    else {
        ret=0;
        wkey_log(LOG_INFO,"Hardware Verification Validated by VaultIC\n");
    }
    
    if(vlt_tls_close()!=0) {
        fprintf(stderr, "ERROR: vlt_tls_close error\n");
    }
    
    return ret;

}

int verifySignatureWithPackageCertificate(config_values_t config,char*binaryPath, char* c_sigBuf, char* signingCertificate)
{
    wkey_log(LOG_STEP_INDICATOR,"Verify the Signature of the Package With package certificate");
    int ret;

    ecc_key eccKey;

    int fileLen;
    byte *fileBuf = NULL;

    word32 i_sigLen = strlen(c_sigBuf);

    byte* sigBuf;
    word32 sigBufLen = i_sigLen;

    sigBuf=(byte*)malloc(i_sigLen);

    unsigned char* signing_CertificateWithHeader;
    /*add header and footer to pem*/
    signing_CertificateWithHeader = malloc(strlen(signingCertificate)+strlen(PEM_TEMPLATE));
    sprintf(signing_CertificateWithHeader,PEM_TEMPLATE,signingCertificate);

    if(load_file_to_buffer(binaryPath, &fileBuf, &fileLen)<0)
    {
        wkey_log(LOG_ERROR, "while loading Binary File : %s",binaryPath);
    }

    /* Release and init new key */
    wc_ecc_init(&eccKey);

    if((ret=load_Public_key_from_x509_pem_string(signing_CertificateWithHeader, &eccKey))<0)
    {
        wkey_log(LOG_ERROR, "while loading Public Key Signing Certificate File");
    }

    if((ret=Base64_Decode(c_sigBuf,i_sigLen,sigBuf,&sigBufLen))<0)
    {
        wkey_log(LOG_ERROR, "while convert base64 signature to binary %d",ret);
    }

    /* Perform signature verification using public key */
    wkey_log(LOG_INFO,"Software Verification of Signature by WolfSSL");
    if(ret=wc_SignatureVerify(6, 1,fileBuf, fileLen,sigBuf, sigBufLen,&eccKey, sizeof(eccKey))<0)
    {
        wkey_log(LOG_ERROR,"Invalid Package Signature");
        ret = EXIT_FAILURE;
    }

    /* Check requested curve */
    if( eccKey.dp->id == ECC_SECP256R1 )
    {
        wkey_log(LOG_INFO,"Hardware Verification of Signature by WolfSSL");
        if(ret=VAULT_IC_SignatureVerify(fileBuf, fileLen,sigBuf, sigBufLen,&eccKey, sizeof(eccKey))<0)
        {
            wkey_log(LOG_ERROR,"VAULT-IC Invalid Package Signature %d ",ret);
            ret = -1;
        }
    }
    else
    {  
        wkey_log(LOG_WARNING,"VAULT-IC can only verify ECC_SECP256R1 key type signature ");
    }

    wc_ecc_free(&eccKey);
    free(sigBuf);
    free(signing_CertificateWithHeader);
    free(fileBuf);
    
    return ret;
}

int ValidateCertificateByInes(config_values_t config,char* signingCertificatePath)
{
    wkey_log(LOG_STEP_INDICATOR,"Verify Certificate Status (not revoked) with INeS CMS");

    int ret=-1;
    certificate_status_t signingCertificate_Status;
    
    signingCertificate_Status = apiREST_validateCertificate(config,signingCertificatePath);

    if(strcmp(signingCertificate_Status.status,"Good")==0)
    {
        ret=0;
    }

    return ret;
}

int verifyCertificateChain(config_values_t config,char* caCert,char* signingCertificate)
{
    wkey_log(LOG_STEP_INDICATOR,"Verify Certificate Root of Trust");

    int ret = -1;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    int sizeof_CA_cert=0;

    wolfSSL_Init();

    if(vlt_tls_init() !=0) {
        wkey_log(LOG_ERROR,"ERROR: vic_tls_init error\n");
    }

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        printf("wolfSSL_CertManagerNew() failed\n");
        return -1;
    }

    /* Read Device certificate in VaultIC */
    printf("Read Device Certificate in VaultIC at index : %d\n",SSL_VIC_DEVICE_CERT);
    if ((sizeof_CA_cert = vlt_tls_get_cert_size(SSL_VIC_DEVICE_CERT)) == -1) {
        printf("ERROR: No Device Certificate found in VaultIC\n");
        return -1;
    }

    caCert = XMALLOC(sizeof_CA_cert, NULL, DYNAMIC_TYPE_ECC_BUFFER);
    if (ret=vlt_tls_read_cert(caCert, SSL_VIC_DEVICE_CERT) !=0 ) {
        wkey_log(LOG_ERROR,"ERROR: vlt_tls_read_cert Device %d\n",ret);
    }

    ret =  	wolfSSL_CertManagerLoadCABuffer(cm, caCert,sizeof_CA_cert,SSL_FILETYPE_DEFAULT);
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_CertManagerLoadCABuffer() failed (%d): %s\n",ret, wolfSSL_ERR_reason_error_string(ret));
    }

    XFREE(caCert, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /*add header and footer to pem*/
    unsigned char* signing_CertificateWithHeader = malloc(strlen(signingCertificate)+strlen(PEM_TEMPLATE));
    sprintf(signing_CertificateWithHeader,PEM_TEMPLATE,signingCertificate);

    ret = wolfSSL_CertManagerVerifyBuffer(cm, signing_CertificateWithHeader, strlen(signing_CertificateWithHeader), SSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_CertManagerVerify() failed (%d): %s\n",ret, wolfSSL_ERR_reason_error_string(ret));
    }

    if(vlt_tls_close()!=0) {
        fprintf(stderr, "ERROR: vlt_tls_close error\n");
    }

    free(signing_CertificateWithHeader);

    if(ret == WOLFSSL_SUCCESS)
        return 0;

    return -1;

}

int main(int argc, char **argv)
{
    int packageSignature = -1;
    int chainValidation = -1;
    int revocationStatus = -1;
    int ret=0;
    config_values_t config;
    
    /* Extract the data from the SealSQ config file */
    
    initConfigFile(&config);

    for (int i = 0; i < argc; i++) {
        
        if(strcmp(argv[i],"-c")==0)
        {
            if(argv[i+1]!=NULL)
            {
                ret = parseConfigFile(argv[i+1], &config);
            }

        }
    }

    if (verifyConfigStruc(CONFIG_FILE_SOFTWARE_SIGNING, &config)<0)
    {
        wkey_log(LOG_ERROR, "Invalid configuration, please verify");
        ret=-1;
    }

    //wolfSSL_Debugging_ON();

    /* Extract the data from the Package manifest */
    char* manifestJsonFile = openFile(config.SOFTWARE_MANIFEST_PATH);
    if (!manifestJsonFile)
    {
        wkey_log(LOG_ERROR,"error while opening Manifest File");
        return -1;
    }

    json_value* jsonmanifest = convertStringIntoJsontype(manifestJsonFile);
    char* signing_Certificate = extractJsonValue(jsonmanifest, "certificate",NULL);
    char* softwareSignature = extractJsonValue(jsonmanifest, "manifest-signature",NULL);

    /* Perform verify */
    packageSignature = verifySignatureWithPackageCertificate(config,config.SOFTWARE_BINARY_PATH,softwareSignature,signing_Certificate);
    chainValidation = verifyCertificateChain(config,config.CA_CERT_PATH,signing_Certificate);
    revocationStatus = ValidateCertificateByInes(config,signing_Certificate);

    /* Display results */
    if(packageSignature==0)
    {
        wkey_log(LOG_SUCCESS,"Package Signature Validated");
    }
    else
    {
        wkey_log(LOG_ERROR,"Package Signature INVALID");
        ret = -1;
    }

    if(chainValidation==0)
    {
        wkey_log(LOG_SUCCESS,"Certificate Root of Trust Validated");
    }
    else
    {
        wkey_log(LOG_ERROR,"Certificate Root of Trust INVALID");
        ret = -1;
    }

    if(revocationStatus==0)
    {
        wkey_log(LOG_SUCCESS,"Signing Certificate Validated By INeS");
    }
    else
    {
        wkey_log(LOG_ERROR,"Signing Certificate INVALID By INeS");
        ret = -1;
    }

    if(ret==0)
    {
        wkey_log(LOG_SUCCESS,"This Software (%s) is VALIDATED and can be TRUSTED",config.SOFTWARE_BINARY_PATH);
    }
    else
    {
        wkey_log(LOG_ERROR,"This Software (%s) is INVALID, It had been falsified",config.SOFTWARE_BINARY_PATH);
        ret = -1;
    }
    
    free(manifestJsonFile);
    free(jsonmanifest);
    free(signing_Certificate);
    free(softwareSignature);
    freeConfigStruct(&config);

    return 0;
}