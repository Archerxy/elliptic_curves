#include <jni.h>
#include <stdio.h>

/**
* gcc -fPIC -shared jniclog.c -o libclog.dll -static-libgcc -static-libstdc++
*/

#ifndef _Included_com_whty_cross_core_log_Logger
#define _Included_com_whty_cross_core_log_Logger
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL Java_com_whty_cross_core_log_Logger_clog
  (JNIEnv *env, jclass clazz, jstring j_msg) {
    if(NULL == j_msg) {
        return ;
    }
    const char *msg = (*env)->GetStringUTFChars(env, j_msg, NULL);
    printf("%s \n", msg);
    fflush(stdout);
    
    if(msg) {
        (*env)->ReleaseStringUTFChars(env, j_msg, msg);
    }
  }

#ifdef __cplusplus
}
#endif
#endif