#include <jni.h>
#include <android/log.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


jbyteArray as_byte_array(JNIEnv *env, unsigned char *buf, int len) {
    jbyteArray array = env->NewByteArray(len);
    env->SetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte *>(buf));
    return array;
}

unsigned char *as_unsigned_char_array(JNIEnv *env, jbyteArray array) {
    int len = env->GetArrayLength(array);
    unsigned char *buf = new unsigned char[len];
    env->GetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte *>(buf));
    return buf;
}

/**
 * @see https://developer.android.com/training/articles/perf-jni.html
 */

/**
 * void net.kibotu.openssl.jni.NativeOpenSSL#init()
 */
extern "C" void Java_net_kibotu_openssl_jni_NativeOpenSSL_init(JNIEnv *env,
                                                                         jobject /* this */) {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    __android_log_print(ANDROID_LOG_VERBOSE, "[JNI]", "Initializing.");
}

/**
 * byte[] net.kibotu.openssl.jni.NativeOpenSSL#encrypt(byte[], String)
 */
extern "C" jbyteArray Java_net_kibotu_openssl_jni_NativeOpenSSL_encrypt(JNIEnv *env,
                                                                                  jobject /* this */,
                                                                                  jbyteArray jPassword,
                                                                                  jbyteArray jPayload) {

    unsigned char *cipher = as_unsigned_char_array(env, jPassword);
    unsigned char *payload = as_unsigned_char_array(env, jPayload);

    int payloadLength = env->GetArrayLength(jPayload);
    int resultLength = ((payloadLength / 16) + 1) * 16;
    unsigned char *result = (unsigned char *) malloc((size_t) resultLength);
    if (result == NULL) {
        // todo free
        return 0;
    }

    AES_KEY enc_key;
    AES_set_encrypt_key(cipher, 8 * 16, &enc_key);

    AES_cbc_encrypt(payload, result, (size_t) resultLength, &enc_key, cipher, AES_ENCRYPT);

    jbyteArray jResult = as_byte_array(env, result, resultLength);

    free(result);

    return jResult;
}

/**
 * String net.kibotu.openssl.jni.NativeOpenSSL#decrypt(byte[], byte[])
 */
extern "C" jbyteArray Java_net_kibotu_openssl_jni_NativeOpenSSL_decrypt(JNIEnv *env,
                                                                                  jobject /* this */,
                                                                                  jbyteArray jPassword,
                                                                                  jbyteArray jEncrypted) {

    unsigned char *cipher = as_unsigned_char_array(env, jPassword);
    unsigned char *encrypted = as_unsigned_char_array(env, jEncrypted);

    int encryptedLength = env->GetArrayLength(jEncrypted);
    unsigned char *result = (unsigned char *) malloc((size_t) encryptedLength);
    if (result == NULL) {
        // todo free
        return 0;
    }

    AES_KEY enc_key;
    AES_set_decrypt_key(cipher, 8 * 16, &enc_key);

    AES_cbc_encrypt(encrypted, result, (size_t) encryptedLength, &enc_key, cipher, AES_DECRYPT);

    jbyteArray jResult = as_byte_array(env, result, encryptedLength);

    free(result);

    return jResult;
}




















