/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.2
 *
 * This file is not intended to be easily readable and contains a number of
 * coding conventions designed to improve portability and efficiency. Do not make
 * changes to this file unless you know what you are doing--modify the SWIG
 * interface file instead.
 * ----------------------------------------------------------------------------- */

#define SWIGCSHARP


#ifdef __cplusplus
/* SwigValueWrapper is described in swig.swg */
template<typename T> class SwigValueWrapper {
  struct SwigMovePointer {
    T *ptr;
    SwigMovePointer(T *p) : ptr(p) { }
    ~SwigMovePointer() { delete ptr; }
    SwigMovePointer& operator=(SwigMovePointer& rhs) { T* oldptr = ptr; ptr = 0; delete oldptr; ptr = rhs.ptr; rhs.ptr = 0; return *this; }
  } pointer;
  SwigValueWrapper& operator=(const SwigValueWrapper<T>& rhs);
  SwigValueWrapper(const SwigValueWrapper<T>& rhs);
public:
  SwigValueWrapper() : pointer(0) { }
  SwigValueWrapper& operator=(const T& t) { SwigMovePointer tmp(new T(t)); pointer = tmp; return *this; }
  operator T&() const { return *pointer.ptr; }
  T *operator&() { return pointer.ptr; }
};

template <typename T> T SwigValueInit() {
  return T();
}
#endif

/* -----------------------------------------------------------------------------
 *  This section contains generic SWIG labels for method/variable
 *  declarations/attributes, and other compiler dependent labels.
 * ----------------------------------------------------------------------------- */

/* template workaround for compilers that cannot correctly implement the C++ standard */
#ifndef SWIGTEMPLATEDISAMBIGUATOR
# if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x560)
#  define SWIGTEMPLATEDISAMBIGUATOR template
# elif defined(__HP_aCC)
/* Needed even with `aCC -AA' when `aCC -V' reports HP ANSI C++ B3910B A.03.55 */
/* If we find a maximum version that requires this, the test would be __HP_aCC <= 35500 for A.03.55 */
#  define SWIGTEMPLATEDISAMBIGUATOR template
# else
#  define SWIGTEMPLATEDISAMBIGUATOR
# endif
#endif

/* inline attribute */
#ifndef SWIGINLINE
# if defined(__cplusplus) || (defined(__GNUC__) && !defined(__STRICT_ANSI__))
#   define SWIGINLINE inline
# else
#   define SWIGINLINE
# endif
#endif

/* attribute recognised by some compilers to avoid 'unused' warnings */
#ifndef SWIGUNUSED
# if defined(__GNUC__)
#   if !(defined(__cplusplus)) || (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#     define SWIGUNUSED __attribute__ ((__unused__))
#   else
#     define SWIGUNUSED
#   endif
# elif defined(__ICC)
#   define SWIGUNUSED __attribute__ ((__unused__))
# else
#   define SWIGUNUSED
# endif
#endif

#ifndef SWIG_MSC_UNSUPPRESS_4505
# if defined(_MSC_VER)
#   pragma warning(disable : 4505) /* unreferenced local function has been removed */
# endif
#endif

#ifndef SWIGUNUSEDPARM
# ifdef __cplusplus
#   define SWIGUNUSEDPARM(p)
# else
#   define SWIGUNUSEDPARM(p) p SWIGUNUSED
# endif
#endif

/* internal SWIG method */
#ifndef SWIGINTERN
# define SWIGINTERN static SWIGUNUSED
#endif

/* internal inline SWIG method */
#ifndef SWIGINTERNINLINE
# define SWIGINTERNINLINE SWIGINTERN SWIGINLINE
#endif

/* exporting methods */
#if (__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#  ifndef GCC_HASCLASSVISIBILITY
#    define GCC_HASCLASSVISIBILITY
#  endif
#endif

#ifndef SWIGEXPORT
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   if defined(STATIC_LINKED)
#     define SWIGEXPORT
#   else
#     define SWIGEXPORT __declspec(dllexport)
#   endif
# else
#   if defined(__GNUC__) && defined(GCC_HASCLASSVISIBILITY)
#     define SWIGEXPORT __attribute__ ((visibility("default")))
#   else
#     define SWIGEXPORT
#   endif
# endif
#endif

/* calling conventions for Windows */
#ifndef SWIGSTDCALL
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   define SWIGSTDCALL __stdcall
# else
#   define SWIGSTDCALL
# endif
#endif

/* Deal with Microsoft's attempt at deprecating C standard runtime functions */
#if !defined(SWIG_NO_CRT_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
# define _CRT_SECURE_NO_DEPRECATE
#endif

/* Deal with Microsoft's attempt at deprecating methods in the standard C++ library */
#if !defined(SWIG_NO_SCL_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_SCL_SECURE_NO_DEPRECATE)
# define _SCL_SECURE_NO_DEPRECATE
#endif



#include <stdlib.h>
#include <string.h>
#include <stdio.h>


/* Support for throwing C# exceptions from C/C++. There are two types: 
 * Exceptions that take a message and ArgumentExceptions that take a message and a parameter name. */
typedef enum {
  SWIG_CSharpApplicationException,
  SWIG_CSharpArithmeticException,
  SWIG_CSharpDivideByZeroException,
  SWIG_CSharpIndexOutOfRangeException,
  SWIG_CSharpInvalidCastException,
  SWIG_CSharpInvalidOperationException,
  SWIG_CSharpIOException,
  SWIG_CSharpNullReferenceException,
  SWIG_CSharpOutOfMemoryException,
  SWIG_CSharpOverflowException,
  SWIG_CSharpSystemException
} SWIG_CSharpExceptionCodes;

typedef enum {
  SWIG_CSharpArgumentException,
  SWIG_CSharpArgumentNullException,
  SWIG_CSharpArgumentOutOfRangeException
} SWIG_CSharpExceptionArgumentCodes;

typedef void (SWIGSTDCALL* SWIG_CSharpExceptionCallback_t)(const char *);
typedef void (SWIGSTDCALL* SWIG_CSharpExceptionArgumentCallback_t)(const char *, const char *);

typedef struct {
  SWIG_CSharpExceptionCodes code;
  SWIG_CSharpExceptionCallback_t callback;
} SWIG_CSharpException_t;

typedef struct {
  SWIG_CSharpExceptionArgumentCodes code;
  SWIG_CSharpExceptionArgumentCallback_t callback;
} SWIG_CSharpExceptionArgument_t;

static SWIG_CSharpException_t SWIG_csharp_exceptions[] = {
  { SWIG_CSharpApplicationException, NULL },
  { SWIG_CSharpArithmeticException, NULL },
  { SWIG_CSharpDivideByZeroException, NULL },
  { SWIG_CSharpIndexOutOfRangeException, NULL },
  { SWIG_CSharpInvalidCastException, NULL },
  { SWIG_CSharpInvalidOperationException, NULL },
  { SWIG_CSharpIOException, NULL },
  { SWIG_CSharpNullReferenceException, NULL },
  { SWIG_CSharpOutOfMemoryException, NULL },
  { SWIG_CSharpOverflowException, NULL },
  { SWIG_CSharpSystemException, NULL }
};

static SWIG_CSharpExceptionArgument_t SWIG_csharp_exceptions_argument[] = {
  { SWIG_CSharpArgumentException, NULL },
  { SWIG_CSharpArgumentNullException, NULL },
  { SWIG_CSharpArgumentOutOfRangeException, NULL }
};

static void SWIGUNUSED SWIG_CSharpSetPendingException(SWIG_CSharpExceptionCodes code, const char *msg) {
  SWIG_CSharpExceptionCallback_t callback = SWIG_csharp_exceptions[SWIG_CSharpApplicationException].callback;
  if ((size_t)code < sizeof(SWIG_csharp_exceptions)/sizeof(SWIG_CSharpException_t)) {
    callback = SWIG_csharp_exceptions[code].callback;
  }
  callback(msg);
}

static void SWIGUNUSED SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpExceptionArgumentCodes code, const char *msg, const char *param_name) {
  SWIG_CSharpExceptionArgumentCallback_t callback = SWIG_csharp_exceptions_argument[SWIG_CSharpArgumentException].callback;
  if ((size_t)code < sizeof(SWIG_csharp_exceptions_argument)/sizeof(SWIG_CSharpExceptionArgument_t)) {
    callback = SWIG_csharp_exceptions_argument[code].callback;
  }
  callback(msg, param_name);
}


#ifdef __cplusplus
extern "C" 
#endif
SWIGEXPORT void SWIGSTDCALL SWIGRegisterExceptionCallbacks_jclmsCCB2014(
                                                SWIG_CSharpExceptionCallback_t applicationCallback,
                                                SWIG_CSharpExceptionCallback_t arithmeticCallback,
                                                SWIG_CSharpExceptionCallback_t divideByZeroCallback, 
                                                SWIG_CSharpExceptionCallback_t indexOutOfRangeCallback, 
                                                SWIG_CSharpExceptionCallback_t invalidCastCallback,
                                                SWIG_CSharpExceptionCallback_t invalidOperationCallback,
                                                SWIG_CSharpExceptionCallback_t ioCallback,
                                                SWIG_CSharpExceptionCallback_t nullReferenceCallback,
                                                SWIG_CSharpExceptionCallback_t outOfMemoryCallback, 
                                                SWIG_CSharpExceptionCallback_t overflowCallback, 
                                                SWIG_CSharpExceptionCallback_t systemCallback) {
  SWIG_csharp_exceptions[SWIG_CSharpApplicationException].callback = applicationCallback;
  SWIG_csharp_exceptions[SWIG_CSharpArithmeticException].callback = arithmeticCallback;
  SWIG_csharp_exceptions[SWIG_CSharpDivideByZeroException].callback = divideByZeroCallback;
  SWIG_csharp_exceptions[SWIG_CSharpIndexOutOfRangeException].callback = indexOutOfRangeCallback;
  SWIG_csharp_exceptions[SWIG_CSharpInvalidCastException].callback = invalidCastCallback;
  SWIG_csharp_exceptions[SWIG_CSharpInvalidOperationException].callback = invalidOperationCallback;
  SWIG_csharp_exceptions[SWIG_CSharpIOException].callback = ioCallback;
  SWIG_csharp_exceptions[SWIG_CSharpNullReferenceException].callback = nullReferenceCallback;
  SWIG_csharp_exceptions[SWIG_CSharpOutOfMemoryException].callback = outOfMemoryCallback;
  SWIG_csharp_exceptions[SWIG_CSharpOverflowException].callback = overflowCallback;
  SWIG_csharp_exceptions[SWIG_CSharpSystemException].callback = systemCallback;
}

#ifdef __cplusplus
extern "C" 
#endif
SWIGEXPORT void SWIGSTDCALL SWIGRegisterExceptionArgumentCallbacks_jclmsCCB2014(
                                                SWIG_CSharpExceptionArgumentCallback_t argumentCallback,
                                                SWIG_CSharpExceptionArgumentCallback_t argumentNullCallback,
                                                SWIG_CSharpExceptionArgumentCallback_t argumentOutOfRangeCallback) {
  SWIG_csharp_exceptions_argument[SWIG_CSharpArgumentException].callback = argumentCallback;
  SWIG_csharp_exceptions_argument[SWIG_CSharpArgumentNullException].callback = argumentNullCallback;
  SWIG_csharp_exceptions_argument[SWIG_CSharpArgumentOutOfRangeException].callback = argumentOutOfRangeCallback;
}


/* Callback for returning strings to C# without leaking memory */
typedef char * (SWIGSTDCALL* SWIG_CSharpStringHelperCallback)(const char *);
static SWIG_CSharpStringHelperCallback SWIG_csharp_string_callback = NULL;


#ifdef __cplusplus
extern "C" 
#endif
SWIGEXPORT void SWIGSTDCALL SWIGRegisterStringCallback_jclmsCCB2014(SWIG_CSharpStringHelperCallback callback) {
  SWIG_csharp_string_callback = callback;
}


/* Contract support */

#define SWIG_contract_assert(nullreturn, expr, msg) if (!(expr)) {SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpArgumentOutOfRangeException, msg, ""); return nullreturn; } else


#include <string>


#define _ZWUSE_AS_JNI
#include "jclmsCCB2014.h"
#include "ECIES708\zwEcies529.h"


#ifdef __cplusplus
extern "C" {
#endif

SWIGEXPORT int SWIGSTDCALL CSharp_ZW_AES_BLOCK_SIZE_get() {
  int jresult ;
  int result;
  
  result = (int)(int)ZW_AES_BLOCK_SIZE;
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_ZW_SM3_DGST_SIZE_get() {
  int jresult ;
  int result;
  
  result = (int)(int)ZW_SM3_DGST_SIZE;
  jresult = result; 
  return jresult;
}


SWIGEXPORT void SWIGSTDCALL CSharp_JCMATCH_s_datetime_set(void * jarg1, int jarg2) {
  jcLockReverseMatchResult *arg1 = (jcLockReverseMatchResult *) 0 ;
  int arg2 ;
  
  arg1 = (jcLockReverseMatchResult *)jarg1; 
  arg2 = (int)jarg2; 
  if (arg1) (arg1)->s_datetime = arg2;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JCMATCH_s_datetime_get(void * jarg1) {
  int jresult ;
  jcLockReverseMatchResult *arg1 = (jcLockReverseMatchResult *) 0 ;
  int result;
  
  arg1 = (jcLockReverseMatchResult *)jarg1; 
  result = (int) ((arg1)->s_datetime);
  jresult = result; 
  return jresult;
}


SWIGEXPORT void SWIGSTDCALL CSharp_JCMATCH_s_validity_set(void * jarg1, int jarg2) {
  jcLockReverseMatchResult *arg1 = (jcLockReverseMatchResult *) 0 ;
  int arg2 ;
  
  arg1 = (jcLockReverseMatchResult *)jarg1; 
  arg2 = (int)jarg2; 
  if (arg1) (arg1)->s_validity = arg2;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JCMATCH_s_validity_get(void * jarg1) {
  int jresult ;
  jcLockReverseMatchResult *arg1 = (jcLockReverseMatchResult *) 0 ;
  int result;
  
  arg1 = (jcLockReverseMatchResult *)jarg1; 
  result = (int) ((arg1)->s_validity);
  jresult = result; 
  return jresult;
}


SWIGEXPORT void SWIGSTDCALL CSharp_JCMATCH_s_matchTimes_set(void * jarg1, int jarg2) {
  jcLockReverseMatchResult *arg1 = (jcLockReverseMatchResult *) 0 ;
  int arg2 ;
  
  arg1 = (jcLockReverseMatchResult *)jarg1; 
  arg2 = (int)jarg2; 
  if (arg1) (arg1)->s_matchTimes = arg2;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JCMATCH_s_matchTimes_get(void * jarg1) {
  int jresult ;
  jcLockReverseMatchResult *arg1 = (jcLockReverseMatchResult *) 0 ;
  int result;
  
  arg1 = (jcLockReverseMatchResult *)jarg1; 
  result = (int) ((arg1)->s_matchTimes);
  jresult = result; 
  return jresult;
}


SWIGEXPORT void * SWIGSTDCALL CSharp_new_JCMATCH() {
  void * jresult ;
  jcLockReverseMatchResult *result = 0 ;
  
  result = (jcLockReverseMatchResult *)new jcLockReverseMatchResult();
  jresult = (void *)result; 
  return jresult;
}


SWIGEXPORT void SWIGSTDCALL CSharp_delete_JCMATCH(void * jarg1) {
  jcLockReverseMatchResult *arg1 = (jcLockReverseMatchResult *) 0 ;
  
  arg1 = (jcLockReverseMatchResult *)jarg1; 
  delete arg1;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NUM_VALIDITY_get() {
  int jresult ;
  int result;
  
  result = (int)((8));
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JC_ATMNO_MAXLEN_get() {
  int jresult ;
  int result;
  
  result = (int)((16));
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JC_LOCKNO_MAXLEN_get() {
  int jresult ;
  int result;
  
  result = (int)((16));
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JC_PSK_LEN_get() {
  int jresult ;
  int result;
  
  result = (int)((256/4));
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JC_INVALID_VALUE_get() {
  int jresult ;
  int result;
  
  result = (int)((-1));
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JcLockNew() {
  int jresult ;
  int result;
  
  result = (int)JcLockNew();
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JcLockSetInt(int jarg1, int jarg2, int jarg3) {
  int jresult ;
  int arg1 ;
  JCITYPE arg2 ;
  int arg3 ;
  JCERROR result;
  
  arg1 = (int)jarg1; 
  arg2 = (JCITYPE)jarg2; 
  arg3 = (int)jarg3; 
  result = (JCERROR)JcLockSetInt(arg1,arg2,arg3);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JcLockSetString(int jarg1, int jarg2, char * jarg3) {
  int jresult ;
  int arg1 ;
  JCITYPE arg2 ;
  char *arg3 = (char *) 0 ;
  JCERROR result;
  
  arg1 = (int)jarg1; 
  arg2 = (JCITYPE)jarg2; 
  arg3 = (char *)jarg3; 
  result = (JCERROR)JcLockSetString(arg1,arg2,(char const *)arg3);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JcLockSetCmdType(int jarg1, int jarg2, int jarg3) {
  int jresult ;
  int arg1 ;
  JCITYPE arg2 ;
  JCCMD arg3 ;
  JCERROR result;
  
  arg1 = (int)jarg1; 
  arg2 = (JCITYPE)jarg2; 
  arg3 = (JCCMD)jarg3; 
  result = (JCERROR)JcLockSetCmdType(arg1,arg2,arg3);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JcLockCheckInput(int jarg1) {
  int jresult ;
  int arg1 ;
  JCERROR result;
  
  arg1 = (int)jarg1; 
  result = (JCERROR)JcLockCheckInput(arg1);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JcLockGetDynaCode(int jarg1) {
  int jresult ;
  int arg1 ;
  int result;
  
  arg1 = (int)jarg1; 
  result = (int)JcLockGetDynaCode(arg1);
  jresult = result; 
  return jresult;
}


SWIGEXPORT void * SWIGSTDCALL CSharp_JcLockReverseVerifyDynaCode(int jarg1, int jarg2) {
  void * jresult ;
  int arg1 ;
  int arg2 ;
  JCMATCH result;
  
  arg1 = (int)jarg1; 
  arg2 = (int)jarg2; 
  result = JcLockReverseVerifyDynaCode(arg1,arg2);
  jresult = new JCMATCH((const JCMATCH &)result); 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_JcLockGetVersion() {
  int jresult ;
  int result;
  
  result = (int)JcLockGetVersion();
  jresult = result; 
  return jresult;
}


SWIGEXPORT void SWIGSTDCALL CSharp_JcLockDebugPrint(int jarg1) {
  int arg1 ;
  
  arg1 = (int)jarg1; 
  JcLockDebugPrint(arg1);
}


SWIGEXPORT int SWIGSTDCALL CSharp_ZWEFS_get() {
  int jresult ;
  int result;
  
  result = (int)(int)ZWEFS;
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_ZW_EXA_get() {
  int jresult ;
  int result;
  
  result = (int)(int)ZW_EXA;
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_zwEciesKeyPairGen(char * jarg1, char * jarg2, int jarg3, char * jarg4, int jarg5) {
  int jresult ;
  char *arg1 = (char *) 0 ;
  char *arg2 = (char *) 0 ;
  int arg3 ;
  char *arg4 = (char *) 0 ;
  int arg5 ;
  int result;
  
  arg1 = (char *)jarg1; 
  arg2 = (char *)jarg2; 
  arg3 = (int)jarg3; 
  arg4 = (char *)jarg4; 
  arg5 = (int)jarg5; 
  result = (int)zwEciesKeyPairGen((char const *)arg1,arg2,arg3,arg4,arg5);
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_zwEciesEncrypt(char * jarg1, char * jarg2, char * jarg3, int jarg4, char * jarg5, int jarg6, char * jarg7, int jarg8) {
  int jresult ;
  char *arg1 = (char *) 0 ;
  char *arg2 = (char *) 0 ;
  char *arg3 = (char *) 0 ;
  int arg4 ;
  char *arg5 = (char *) 0 ;
  int arg6 ;
  char *arg7 = (char *) 0 ;
  int arg8 ;
  int result;
  
  arg1 = (char *)jarg1; 
  arg2 = (char *)jarg2; 
  arg3 = (char *)jarg3; 
  arg4 = (int)jarg4; 
  arg5 = (char *)jarg5; 
  arg6 = (int)jarg6; 
  arg7 = (char *)jarg7; 
  arg8 = (int)jarg8; 
  result = (int)zwEciesEncrypt((char const *)arg1,(char const *)arg2,arg3,arg4,arg5,arg6,arg7,arg8);
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_zwEciesDecrypt(char * jarg1, char * jarg2, int jarg3, char * jarg4, char * jarg5, char * jarg6) {
  int jresult ;
  char *arg1 = (char *) 0 ;
  char *arg2 = (char *) 0 ;
  int arg3 ;
  char *arg4 = (char *) 0 ;
  char *arg5 = (char *) 0 ;
  char *arg6 = (char *) 0 ;
  int result;
  
  arg1 = (char *)jarg1; 
  arg2 = (char *)jarg2; 
  arg3 = (int)jarg3; 
  arg4 = (char *)jarg4; 
  arg5 = (char *)jarg5; 
  arg6 = (char *)jarg6; 
  result = (int)zwEciesDecrypt((char const *)arg1,arg2,arg3,(char const *)arg4,(char const *)arg5,(char const *)arg6);
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_EciesGenKeyPair() {
  int jresult ;
  int result;
  
  result = (int)EciesGenKeyPair();
  jresult = result; 
  return jresult;
}


SWIGEXPORT void SWIGSTDCALL CSharp_EciesDelete(int jarg1) {
  int arg1 ;
  
  arg1 = (int)jarg1; 
  EciesDelete(arg1);
}


SWIGEXPORT char * SWIGSTDCALL CSharp_EciesGetPubKey(int jarg1) {
  char * jresult ;
  int arg1 ;
  char *result = 0 ;
  
  arg1 = (int)jarg1; 
  result = (char *)EciesGetPubKey(arg1);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_EciesGetPriKey(int jarg1) {
  char * jresult ;
  int arg1 ;
  char *result = 0 ;
  
  arg1 = (int)jarg1; 
  result = (char *)EciesGetPriKey(arg1);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_EciesEncrypt(char * jarg1, char * jarg2) {
  char * jresult ;
  char *arg1 = (char *) 0 ;
  char *arg2 = (char *) 0 ;
  char *result = 0 ;
  
  arg1 = (char *)jarg1; 
  arg2 = (char *)jarg2; 
  result = (char *)EciesEncrypt((char const *)arg1,(char const *)arg2);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_EciesDecrypt(char * jarg1, char * jarg2) {
  char * jresult ;
  char *arg1 = (char *) 0 ;
  char *arg2 = (char *) 0 ;
  char *result = 0 ;
  
  arg1 = (char *)jarg1; 
  arg2 = (char *)jarg2; 
  result = (char *)EciesDecrypt((char const *)arg1,(char const *)arg2);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_zwMergePsk(char * jarg1) {
  char * jresult ;
  char *arg1 = (char *) 0 ;
  char *result = 0 ;
  
  arg1 = (char *)jarg1; 
  result = (char *)zwMergePsk((char const *)arg1);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  return jresult;
}


#ifdef __cplusplus
}
#endif

