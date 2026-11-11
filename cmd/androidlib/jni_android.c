//go:build cgo

/*
 * JNI bridge between Kotlin and the Go core, compiled into libyuhaiin.so itself
 * (one library: System.loadLibrary("yuhaiin") loads the Go runtime and this
 * bridge together; see yuhaiin_abi.h).
 *
 * Kotlin -> Go: NativeBridge.nativeCall maps onto yh_call.
 * Go -> Kotlin: yh_host callbacks run on Go-owned threads and call the single
 *   io.github.asutorufa.yuhaiin.core.NativeHost instance.
 *
 * Rules kept here:
 *  - A JNIEnv is never shared between threads: each callback fetches the env of
 *    its own thread, attaching Go threads once and detaching them when the
 *    thread exits (pthread key destructor).
 *  - Classes and method IDs are resolved once in JNI_OnLoad, where the app
 *    class loader is available, and held as global references. Native threads
 *    can not resolve app classes themselves.
 *  - Every callback runs in its own local reference frame, so an attached
 *    thread that never returns to Java can not leak local references.
 *  - A pending Java exception never escapes a callback: it is cleared and
 *    reported to the core as a failure.
 *  - Strings that can contain arbitrary text cross as byte[] (UTF-8), never
 *    through NewStringUTF, which only accepts modified UTF-8.
 */
#include <android/log.h>
#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "yuhaiin_abi.h"

#define TAG "yuhaiin-jni"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define NATIVE_PKG "io/github/asutorufa/yuhaiin/core/"

static JavaVM *g_vm;
static pthread_key_t g_detach_key;

static jclass g_exception_class; /* NativeException */
static jmethodID g_exception_ctor; /* (ILjava/lang/String;)V */
static jclass g_bytes_class; /* byte[] */
static jclass g_string_class;
static jmethodID g_string_ctor; /* String(byte[], String) */
static jstring g_utf8; /* global ref "UTF-8" */
static jclass g_throwable_class;
static jmethodID g_throwable_to_string;

static jobject g_host; /* NativeHost, global ref, installed once */
static jmethodID g_host_protect;
static jmethodID g_host_bind;
static jmethodID g_host_dump_uid;
static jmethodID g_host_establish;
static jmethodID g_host_call;

/* ---- thread attachment ---- */

static void detach_thread(void *unused) {
  (void)unused;
  (*g_vm)->DetachCurrentThread(g_vm);
}

/* Returns the JNIEnv of the calling thread, attaching it if it is a Go thread. */
static JNIEnv *thread_env(void) {
  JNIEnv *env = NULL;
  jint r = (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6);
  if (r == JNI_OK) return env;
  if (r != JNI_EDETACHED) return NULL;
  if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) return NULL;
  /* Detach when this OS thread exits. */
  pthread_setspecific(g_detach_key, (void *)1);
  return env;
}

/* ---- helpers ---- */

static void clear_exception(JNIEnv *env, const char *where) {
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    LOGE("Java exception in %s", where);
  }
}

static char *dup_bytes(const void *p, size_t n) {
  char *out = malloc(n + 1);
  if (!out) return NULL;
  if (n) memcpy(out, p, n);
  out[n] = 0;
  return out;
}

static jbyteArray new_bytes(JNIEnv *env, const uint8_t *p, size_t n) {
  jbyteArray a = (*env)->NewByteArray(env, (jsize)n);
  if (a && n) (*env)->SetByteArrayRegion(env, a, 0, (jsize)n, (const jbyte *)p);
  return a;
}

/* Decodes UTF-8 bytes into a String (NewStringUTF only accepts modified UTF-8). */
static jstring utf8_string(JNIEnv *env, const uint8_t *p, size_t n) {
  jbyteArray raw = new_bytes(env, p, n);
  if (!raw) return NULL;
  return (jstring)(*env)->NewObject(env, g_string_class, g_string_ctor, raw, g_utf8);
}

/* Copies a byte[] into malloc memory; *len receives the length. */
static uint8_t *copy_bytes(JNIEnv *env, jbyteArray a, size_t *len) {
  jsize n = (*env)->GetArrayLength(env, a);
  uint8_t *out = malloc((size_t)n + 1);
  if (!out) return NULL;
  if (n) (*env)->GetByteArrayRegion(env, a, 0, n, (jbyte *)out);
  *len = (size_t)n;
  return out;
}

/* ---- Go -> Kotlin callbacks ---- */

static int32_t host_protect(void *ctx, int32_t fd) {
  (void)ctx;
  JNIEnv *env = thread_env();
  if (!env || !g_host) return 0;
  (*env)->PushLocalFrame(env, 8);
  jboolean ok = (*env)->CallBooleanMethod(env, g_host, g_host_protect, (jint)fd);
  int failed = (*env)->ExceptionCheck(env);
  clear_exception(env, "protect");
  (*env)->PopLocalFrame(env, NULL);
  return (!failed && ok) ? 1 : 0;
}

static int64_t host_bind(void *ctx, int32_t fd, const char *iface) {
  (void)ctx;
  JNIEnv *env = thread_env();
  if (!env || !g_host) return -1;
  (*env)->PushLocalFrame(env, 8);
  jstring name = (*env)->NewStringUTF(env, iface ? iface : "");
  jlong handle = name ? (*env)->CallLongMethod(env, g_host, g_host_bind, (jint)fd, name) : -1;
  if ((*env)->ExceptionCheck(env)) handle = -1;
  clear_exception(env, "bind");
  (*env)->PopLocalFrame(env, NULL);
  return handle;
}

static int32_t host_dump_uid(void *ctx, int32_t proto, const char *src, int32_t sport,
                             const char *dst, int32_t dport) {
  (void)ctx;
  JNIEnv *env = thread_env();
  if (!env || !g_host) return -1;
  (*env)->PushLocalFrame(env, 8);
  jstring s = (*env)->NewStringUTF(env, src ? src : "");
  jstring d = (*env)->NewStringUTF(env, dst ? dst : "");
  jint uid = (s && d) ? (*env)->CallIntMethod(env, g_host, g_host_dump_uid, (jint)proto, s, (jint)sport, d, (jint)dport) : -1;
  if ((*env)->ExceptionCheck(env)) uid = -1;
  clear_exception(env, "dumpUid");
  (*env)->PopLocalFrame(env, NULL);
  return uid;
}

static int32_t host_establish(void *ctx, int64_t generation, const char *config, char **error) {
  (void)ctx;
  *error = NULL;
  JNIEnv *env = thread_env();
  if (!env || !g_host) {
    *error = dup_bytes("provider_unavailable: JNI host is not available", 47);
    return -1;
  }
  (*env)->PushLocalFrame(env, 8);
  jint fd = -1;
  jbyteArray cfg = new_bytes(env, (const uint8_t *)config, strlen(config));
  jobjectArray err = (*env)->NewObjectArray(env, 1, g_bytes_class, NULL);
  if (cfg && err) {
    fd = (*env)->CallIntMethod(env, g_host, g_host_establish, (jlong)generation, cfg, err);
    if ((*env)->ExceptionCheck(env)) {
      fd = -1;
      clear_exception(env, "establish");
    }
    if (fd < 0) {
      jbyteArray msg = (jbyteArray)(*env)->GetObjectArrayElement(env, err, 0);
      if (msg) {
        size_t n;
        uint8_t *m = copy_bytes(env, msg, &n);
        if (m) {
          m[n] = 0;
          *error = (char *)m;
        }
      }
    }
  }
  (*env)->PopLocalFrame(env, NULL);
  if (fd < 0 && !*error) *error = dup_bytes("provider_unavailable: establish failed", 38);
  return fd;
}

static int32_t host_call(void *ctx, const char *op, const uint8_t *req, size_t req_len,
                         uint8_t **resp, size_t *resp_len) {
  (void)ctx;
  *resp = NULL;
  *resp_len = 0;
  JNIEnv *env = thread_env();
  if (!env || !g_host) {
    *resp = (uint8_t *)dup_bytes("JNI host is not available", 25);
    *resp_len = *resp ? 25 : 0;
    return -1;
  }
  int32_t status = 0;
  (*env)->PushLocalFrame(env, 8);
  jstring name = (*env)->NewStringUTF(env, op);
  jbyteArray in = req_len ? new_bytes(env, req, req_len) : NULL;
  jbyteArray out = NULL;
  if (name && (!req_len || in)) {
    out = (jbyteArray)(*env)->CallObjectMethod(env, g_host, g_host_call, name, in);
  }
  if ((*env)->ExceptionCheck(env)) {
    jthrowable ex = (*env)->ExceptionOccurred(env);
    (*env)->ExceptionClear(env);
    status = -1;
    const char *text = "host call failed";
    jstring js = ex ? (jstring)(*env)->CallObjectMethod(env, ex, g_throwable_to_string) : NULL;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    const char *utf = js ? (*env)->GetStringUTFChars(env, js, NULL) : NULL;
    if (utf) text = utf;
    *resp_len = strlen(text);
    *resp = (uint8_t *)dup_bytes(text, *resp_len);
    if (utf) (*env)->ReleaseStringUTFChars(env, js, utf);
  } else if (out) {
    *resp = copy_bytes(env, out, resp_len);
    if (!*resp) status = -1;
    if (*resp && *resp_len == 0) {
      free(*resp);
      *resp = NULL;
    }
  }
  (*env)->PopLocalFrame(env, NULL);
  return status;
}

/* ---- Kotlin -> Go ---- */

static void throw_native(JNIEnv *env, jint status, const char *message) {
  jstring msg = (*env)->NewStringUTF(env, message);
  jobject ex = msg ? (*env)->NewObject(env, g_exception_class, g_exception_ctor, status, msg) : NULL;
  if (ex) (*env)->Throw(env, (jthrowable)ex);
}

JNIEXPORT jbyteArray JNICALL Java_io_github_asutorufa_yuhaiin_core_NativeBridge_nativeCall(
    JNIEnv *env, jclass clazz, jstring operation, jbyteArray request) {
  (void)clazz;
  if (!operation) {
    throw_native(env, YH_ERR_BAD_REQUEST, "operation is null");
    return NULL;
  }
  const char *op = (*env)->GetStringUTFChars(env, operation, NULL);
  if (!op) return NULL; /* OutOfMemoryError pending */
  size_t req_len = 0;
  uint8_t *req = request ? copy_bytes(env, request, &req_len) : NULL;
  if (request && !req) {
    (*env)->ReleaseStringUTFChars(env, operation, op);
    throw_native(env, YH_ERR, "out of memory");
    return NULL;
  }
  uint8_t *resp = NULL;
  size_t resp_len = 0;
  int32_t status = yh_call(op, req, req_len, &resp, &resp_len);
  free(req);

  jbyteArray result = NULL;
  if (status == YH_OK) {
    result = new_bytes(env, resp, resp_len);
  } else {
    jstring text = utf8_string(env, resp, resp_len);
    jobject ex = text ? (*env)->NewObject(env, g_exception_class, g_exception_ctor, (jint)status, text) : NULL;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (ex) {
      (*env)->Throw(env, (jthrowable)ex);
    } else {
      throw_native(env, status, "native call failed");
    }
  }
  if (resp) yh_free(resp);
  (*env)->ReleaseStringUTFChars(env, operation, op);
  return result;
}

JNIEXPORT jint JNICALL Java_io_github_asutorufa_yuhaiin_core_NativeBridge_nativeAbiVersion(JNIEnv *env, jclass clazz) {
  (void)env;
  (void)clazz;
  return (jint)yh_abi_version();
}

/* Installs the callback table once per process. Returns false if it was
 * already installed (the existing NativeHost keeps serving; its handlers are
 * swapped on the Kotlin side). */
JNIEXPORT jboolean JNICALL Java_io_github_asutorufa_yuhaiin_core_NativeBridge_nativeInstallHost(
    JNIEnv *env, jclass clazz, jobject host) {
  (void)clazz;
  if (g_host) return JNI_FALSE;
  jclass cls = (*env)->GetObjectClass(env, host);
  jmethodID protect = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
  jmethodID bind = (*env)->GetMethodID(env, cls, "bind", "(ILjava/lang/String;)J");
  jmethodID uid = (*env)->GetMethodID(env, cls, "dumpUid", "(ILjava/lang/String;ILjava/lang/String;I)I");
  jmethodID establish = (*env)->GetMethodID(env, cls, "establish", "(J[B[[B)I");
  jmethodID call = (*env)->GetMethodID(env, cls, "call", "(Ljava/lang/String;[B)[B");
  if (!protect || !bind || !uid || !establish || !call) return JNI_FALSE; /* NoSuchMethodError pending */
  g_host_protect = protect;
  g_host_bind = bind;
  g_host_dump_uid = uid;
  g_host_establish = establish;
  g_host_call = call;
  g_host = (*env)->NewGlobalRef(env, host);

  yh_host table;
  memset(&table, 0, sizeof table);
  table.size = sizeof table;
  table.ctx = NULL;
  table.protect = host_protect;
  table.bind_socket = host_bind;
  table.dump_uid = host_dump_uid;
  table.vpn_establish = host_establish;
  table.call = host_call;
  if (yh_set_host(&table) != YH_OK) {
    (*env)->DeleteGlobalRef(env, g_host);
    g_host = NULL;
    return JNI_FALSE;
  }
  return JNI_TRUE;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved;
  g_vm = vm;
  JNIEnv *env;
  if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
  if (pthread_key_create(&g_detach_key, detach_thread) != 0) return JNI_ERR;

  jclass ex = (*env)->FindClass(env, NATIVE_PKG "NativeException");
  jclass bytes = (*env)->FindClass(env, "[B");
  jclass throwable = (*env)->FindClass(env, "java/lang/Throwable");
  jclass string = (*env)->FindClass(env, "java/lang/String");
  if (!ex || !bytes || !throwable || !string) return JNI_ERR;
  g_string_class = (*env)->NewGlobalRef(env, string);
  g_string_ctor = (*env)->GetMethodID(env, string, "<init>", "([BLjava/lang/String;)V");
  jstring utf8 = (*env)->NewStringUTF(env, "UTF-8");
  if (!g_string_ctor || !utf8) return JNI_ERR;
  g_utf8 = (jstring)(*env)->NewGlobalRef(env, utf8);
  g_exception_class = (*env)->NewGlobalRef(env, ex);
  g_bytes_class = (*env)->NewGlobalRef(env, bytes);
  g_throwable_class = (*env)->NewGlobalRef(env, throwable);
  g_exception_ctor = (*env)->GetMethodID(env, ex, "<init>", "(ILjava/lang/String;)V");
  g_throwable_to_string = (*env)->GetMethodID(env, throwable, "toString", "()Ljava/lang/String;");
  if (!g_exception_ctor || !g_throwable_to_string) return JNI_ERR;
  return JNI_VERSION_1_6;
}
