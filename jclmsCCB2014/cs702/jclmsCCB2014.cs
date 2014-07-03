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

public class jclmsCCB2014 {
  public static int zwGetDynaCode(JcLockInput arg0) {
    int ret = jclmsCCB2014PINVOKE.zwGetDynaCode(JcLockInput.getCPtr(arg0));
    if (jclmsCCB2014PINVOKE.SWIGPendingException.Pending) throw jclmsCCB2014PINVOKE.SWIGPendingException.Retrieve();
    return ret;
  }

  public static JCERROR zwVerifyDynaCode(JcLockInput arg0, int dstDyCode) {
    JCERROR ret = (JCERROR)jclmsCCB2014PINVOKE.zwVerifyDynaCode(JcLockInput.getCPtr(arg0), dstDyCode);
    if (jclmsCCB2014PINVOKE.SWIGPendingException.Pending) throw jclmsCCB2014PINVOKE.SWIGPendingException.Retrieve();
    return ret;
  }

  public static int getVersion() {
    int ret = jclmsCCB2014PINVOKE.getVersion();
    return ret;
  }

  public static readonly int ZW_AES_BLOCK_SIZE = jclmsCCB2014PINVOKE.ZW_AES_BLOCK_SIZE_get();
  public static readonly int ZW_SM3_DGST_SIZE = jclmsCCB2014PINVOKE.ZW_SM3_DGST_SIZE_get();
}

}
