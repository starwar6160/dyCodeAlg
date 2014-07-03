/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 2.0.11
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

namespace jclms {

using System;
using System.Runtime.InteropServices;

class jclmsCCB2014PINVOKE {

  protected class SWIGExceptionHelper {

    public delegate void ExceptionDelegate(string message);
    public delegate void ExceptionArgumentDelegate(string message, string paramName);

    static ExceptionDelegate applicationDelegate = new ExceptionDelegate(SetPendingApplicationException);
    static ExceptionDelegate arithmeticDelegate = new ExceptionDelegate(SetPendingArithmeticException);
    static ExceptionDelegate divideByZeroDelegate = new ExceptionDelegate(SetPendingDivideByZeroException);
    static ExceptionDelegate indexOutOfRangeDelegate = new ExceptionDelegate(SetPendingIndexOutOfRangeException);
    static ExceptionDelegate invalidCastDelegate = new ExceptionDelegate(SetPendingInvalidCastException);
    static ExceptionDelegate invalidOperationDelegate = new ExceptionDelegate(SetPendingInvalidOperationException);
    static ExceptionDelegate ioDelegate = new ExceptionDelegate(SetPendingIOException);
    static ExceptionDelegate nullReferenceDelegate = new ExceptionDelegate(SetPendingNullReferenceException);
    static ExceptionDelegate outOfMemoryDelegate = new ExceptionDelegate(SetPendingOutOfMemoryException);
    static ExceptionDelegate overflowDelegate = new ExceptionDelegate(SetPendingOverflowException);
    static ExceptionDelegate systemDelegate = new ExceptionDelegate(SetPendingSystemException);

    static ExceptionArgumentDelegate argumentDelegate = new ExceptionArgumentDelegate(SetPendingArgumentException);
    static ExceptionArgumentDelegate argumentNullDelegate = new ExceptionArgumentDelegate(SetPendingArgumentNullException);
    static ExceptionArgumentDelegate argumentOutOfRangeDelegate = new ExceptionArgumentDelegate(SetPendingArgumentOutOfRangeException);

    [DllImport("jclmsCCB2014", EntryPoint="SWIGRegisterExceptionCallbacks_jclmsCCB2014")]
    public static extern void SWIGRegisterExceptionCallbacks_jclmsCCB2014(
                                ExceptionDelegate applicationDelegate,
                                ExceptionDelegate arithmeticDelegate,
                                ExceptionDelegate divideByZeroDelegate, 
                                ExceptionDelegate indexOutOfRangeDelegate, 
                                ExceptionDelegate invalidCastDelegate,
                                ExceptionDelegate invalidOperationDelegate,
                                ExceptionDelegate ioDelegate,
                                ExceptionDelegate nullReferenceDelegate,
                                ExceptionDelegate outOfMemoryDelegate, 
                                ExceptionDelegate overflowDelegate, 
                                ExceptionDelegate systemExceptionDelegate);

    [DllImport("jclmsCCB2014", EntryPoint="SWIGRegisterExceptionArgumentCallbacks_jclmsCCB2014")]
    public static extern void SWIGRegisterExceptionCallbacksArgument_jclmsCCB2014(
                                ExceptionArgumentDelegate argumentDelegate,
                                ExceptionArgumentDelegate argumentNullDelegate,
                                ExceptionArgumentDelegate argumentOutOfRangeDelegate);

    static void SetPendingApplicationException(string message) {
      SWIGPendingException.Set(new System.ApplicationException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingArithmeticException(string message) {
      SWIGPendingException.Set(new System.ArithmeticException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingDivideByZeroException(string message) {
      SWIGPendingException.Set(new System.DivideByZeroException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingIndexOutOfRangeException(string message) {
      SWIGPendingException.Set(new System.IndexOutOfRangeException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingInvalidCastException(string message) {
      SWIGPendingException.Set(new System.InvalidCastException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingInvalidOperationException(string message) {
      SWIGPendingException.Set(new System.InvalidOperationException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingIOException(string message) {
      SWIGPendingException.Set(new System.IO.IOException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingNullReferenceException(string message) {
      SWIGPendingException.Set(new System.NullReferenceException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingOutOfMemoryException(string message) {
      SWIGPendingException.Set(new System.OutOfMemoryException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingOverflowException(string message) {
      SWIGPendingException.Set(new System.OverflowException(message, SWIGPendingException.Retrieve()));
    }
    static void SetPendingSystemException(string message) {
      SWIGPendingException.Set(new System.SystemException(message, SWIGPendingException.Retrieve()));
    }

    static void SetPendingArgumentException(string message, string paramName) {
      SWIGPendingException.Set(new System.ArgumentException(message, paramName, SWIGPendingException.Retrieve()));
    }
    static void SetPendingArgumentNullException(string message, string paramName) {
      Exception e = SWIGPendingException.Retrieve();
      if (e != null) message = message + " Inner Exception: " + e.Message;
      SWIGPendingException.Set(new System.ArgumentNullException(paramName, message));
    }
    static void SetPendingArgumentOutOfRangeException(string message, string paramName) {
      Exception e = SWIGPendingException.Retrieve();
      if (e != null) message = message + " Inner Exception: " + e.Message;
      SWIGPendingException.Set(new System.ArgumentOutOfRangeException(paramName, message));
    }

    static SWIGExceptionHelper() {
      SWIGRegisterExceptionCallbacks_jclmsCCB2014(
                                applicationDelegate,
                                arithmeticDelegate,
                                divideByZeroDelegate,
                                indexOutOfRangeDelegate,
                                invalidCastDelegate,
                                invalidOperationDelegate,
                                ioDelegate,
                                nullReferenceDelegate,
                                outOfMemoryDelegate,
                                overflowDelegate,
                                systemDelegate);

      SWIGRegisterExceptionCallbacksArgument_jclmsCCB2014(
                                argumentDelegate,
                                argumentNullDelegate,
                                argumentOutOfRangeDelegate);
    }
  }

  protected static SWIGExceptionHelper swigExceptionHelper = new SWIGExceptionHelper();

  public class SWIGPendingException {
    [ThreadStatic]
    private static Exception pendingException = null;
    private static int numExceptionsPending = 0;

    public static bool Pending {
      get {
        bool pending = false;
        if (numExceptionsPending > 0)
          if (pendingException != null)
            pending = true;
        return pending;
      } 
    }

    public static void Set(Exception e) {
      if (pendingException != null)
        throw new ApplicationException("FATAL: An earlier pending exception from unmanaged code was missed and thus not thrown (" + pendingException.ToString() + ")", e);
      pendingException = e;
      lock(typeof(jclmsCCB2014PINVOKE)) {
        numExceptionsPending++;
      }
    }

    public static Exception Retrieve() {
      Exception e = null;
      if (numExceptionsPending > 0) {
        if (pendingException != null) {
          e = pendingException;
          pendingException = null;
          lock(typeof(jclmsCCB2014PINVOKE)) {
            numExceptionsPending--;
          }
        }
      }
      return e;
    }
  }


  protected class SWIGStringHelper {

    public delegate string SWIGStringDelegate(string message);
    static SWIGStringDelegate stringDelegate = new SWIGStringDelegate(CreateString);

    [DllImport("jclmsCCB2014", EntryPoint="SWIGRegisterStringCallback_jclmsCCB2014")]
    public static extern void SWIGRegisterStringCallback_jclmsCCB2014(SWIGStringDelegate stringDelegate);

    static string CreateString(string cString) {
      return cString;
    }

    static SWIGStringHelper() {
      SWIGRegisterStringCallback_jclmsCCB2014(stringDelegate);
    }
  }

  static protected SWIGStringHelper swigStringHelper = new SWIGStringHelper();


  static jclmsCCB2014PINVOKE() {
  }


  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_atmno_set")]
  public static extern void JcLockInput_m_atmno_set(HandleRef jarg1, string jarg2);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_atmno_get")]
  public static extern string JcLockInput_m_atmno_get(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_lockno_set")]
  public static extern void JcLockInput_m_lockno_set(HandleRef jarg1, string jarg2);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_lockno_get")]
  public static extern string JcLockInput_m_lockno_get(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_psk_set")]
  public static extern void JcLockInput_m_psk_set(HandleRef jarg1, string jarg2);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_psk_get")]
  public static extern string JcLockInput_m_psk_get(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_datetime_set")]
  public static extern void JcLockInput_m_datetime_set(HandleRef jarg1, int jarg2);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_datetime_get")]
  public static extern int JcLockInput_m_datetime_get(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_validity_set")]
  public static extern void JcLockInput_m_validity_set(HandleRef jarg1, int jarg2);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_validity_get")]
  public static extern int JcLockInput_m_validity_get(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_closecode_set")]
  public static extern void JcLockInput_m_closecode_set(HandleRef jarg1, int jarg2);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_closecode_get")]
  public static extern int JcLockInput_m_closecode_get(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_cmdtype_set")]
  public static extern void JcLockInput_m_cmdtype_set(HandleRef jarg1, int jarg2);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_m_cmdtype_get")]
  public static extern int JcLockInput_m_cmdtype_get(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_new_JcLockInput")]
  public static extern IntPtr new_JcLockInput();

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_DebugPrint")]
  public static extern void JcLockInput_DebugPrint(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_JcLockInput_CheckInput")]
  public static extern int JcLockInput_CheckInput(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_delete_JcLockInput")]
  public static extern void delete_JcLockInput(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_zwGetDynaCode")]
  public static extern int zwGetDynaCode(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_zwVerifyDynaCode")]
  public static extern int zwVerifyDynaCode(HandleRef jarg1, int jarg2);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_ZW_AES_BLOCK_SIZE_get")]
  public static extern int ZW_AES_BLOCK_SIZE_get();

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_ZW_SM3_DGST_SIZE_get")]
  public static extern int ZW_SM3_DGST_SIZE_get();

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_new_zwHexTool__SWIG_0")]
  public static extern IntPtr new_zwHexTool__SWIG_0(string jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_new_zwHexTool__SWIG_1")]
  public static extern IntPtr new_zwHexTool__SWIG_1(HandleRef jarg1, int jarg2);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_delete_zwHexTool")]
  public static extern void delete_zwHexTool(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_zwHexTool_getBin")]
  public static extern string zwHexTool_getBin(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_zwHexTool_getBinLen")]
  public static extern int zwHexTool_getBinLen(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_zwHexTool_getPadedLen")]
  public static extern int zwHexTool_getPadedLen(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_zwHexTool_getXXTEABlockNum")]
  public static extern int zwHexTool_getXXTEABlockNum(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_zwHexTool_PrintBin")]
  public static extern void zwHexTool_PrintBin(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_zwHexTool_getCArrayStr")]
  public static extern string zwHexTool_getCArrayStr(HandleRef jarg1);

  [DllImport("jclmsCCB2014", EntryPoint="CSharp_zwSm3Hmac7")]
  public static extern IntPtr zwSm3Hmac7(HandleRef jarg1, HandleRef jarg2, HandleRef jarg3);
}

}
