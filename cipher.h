#pragma once
#pragma comment(lib, "Bcrypt.lib")
#include <bcrypt.h>

#define KEYSIZE				32
#define IVSIZE				16
#define okay(msg, ...) \
    printf(msg, ##__VA_ARGS__)


typedef struct _AES {

    PBYTE	pPlainText;				// Base address of the plaintext data 
    DWORD	dwPlainSize;			// Size of the plaintext data

    PBYTE	pCipherText;			// Base address of the encrypted data	
    DWORD	dwCipherSize;			// Size of the encrypted data. This can vary from dwPlainSize when there is padding involved.

    PBYTE	pKey;					// The 32 byte key
    PBYTE	pIv;					// The 16 byte IV

}AES, * PAES;


BOOL InstallAesDecryption(PAES pAes) {

    BOOL				bSTATE = TRUE;

    BCRYPT_ALG_HANDLE		hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE		hKeyHandle = NULL;

    ULONG				cbResult = NULL;
    DWORD				dwBlockSize = NULL;
    DWORD				cbKeyObject = NULL;
    PBYTE				pbKeyObject = NULL;

    PBYTE				pbPlainText = NULL;
    DWORD				cbPlainText = NULL,

        // Intializing "hAlgorithm" as AES algorithm Handle
        STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (STATUS != 0) {
        okay("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto CLEANUP;
    }


    // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (STATUS != 0) {
        okay("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto CLEANUP;
    }


    // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (STATUS != 0) {
        okay("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto CLEANUP;
    }


    // Checking if block size is 16 bytes
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto CLEANUP;
    }


    // Allocating memory for the key object 
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto CLEANUP;
    }


    // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (STATUS != 0) {
        okay("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto CLEANUP;
    }


    // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (STATUS != 0) {
        okay("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto CLEANUP;
    }


    // Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (STATUS != 0) {
        okay("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto CLEANUP;
    }


    // Allocating enough memory for the output buffer, cbPlainText
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto CLEANUP;
    }


    // Running BCryptDecrypt again with pbPlainText as the output buffer
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (STATUS != 0) {
        okay("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto CLEANUP;
    }


    // Clean up
CLEANUP:
    if (hKeyHandle) {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;

}


BOOL Decryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {


    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;


    // Intializing the struct
    AES Aes = {
        .pKey = pKey,
        .pIv = pIv,
        .pCipherText = pCipherTextData,
        .dwCipherSize = sCipherTextSize
    };


    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }


    // Saving output
    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;


    return TRUE;
}