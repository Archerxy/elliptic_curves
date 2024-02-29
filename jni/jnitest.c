#include <jni.h>
#include <stdio.h>


#ifndef _Included_com_whty_cross_core_utils_algorithm_JniTest
#define _Included_com_whty_cross_core_utils_algorithm_JniTest
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL Java_com_whty_cross_core_utils_algorithm_JniTest_print
  (JNIEnv *env, jclass clazz) {
      printf("hello, jni\n");
  }

#ifdef __cplusplus
}
#endif
#endif