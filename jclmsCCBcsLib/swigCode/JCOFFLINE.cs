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

public class JCOFFLINE : IDisposable {
  private HandleRef swigCPtr;
  protected bool swigCMemOwn;

  internal JCOFFLINE(IntPtr cPtr, bool cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = new HandleRef(this, cPtr);
  }

  internal static HandleRef getCPtr(JCOFFLINE obj) {
    return (obj == null) ? new HandleRef(null, IntPtr.Zero) : obj.swigCPtr;
  }

  ~JCOFFLINE() {
    Dispose();
  }

  public virtual void Dispose() {
    lock(this) {
      if (swigCPtr.Handle != IntPtr.Zero) {
        if (swigCMemOwn) {
          swigCMemOwn = false;
          jclmsCCB2014PINVOKE.delete_JCOFFLINE(swigCPtr);
        }
        swigCPtr = new HandleRef(null, IntPtr.Zero);
      }
      GC.SuppressFinalize(this);
    }
  }

  public int s_datetime {
    set {
      jclmsCCB2014PINVOKE.JCOFFLINE_s_datetime_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JCOFFLINE_s_datetime_get(swigCPtr);
      return ret;
    } 
  }

  public int s_validity {
    set {
      jclmsCCB2014PINVOKE.JCOFFLINE_s_validity_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JCOFFLINE_s_validity_get(swigCPtr);
      return ret;
    } 
  }

  public JCOFFLINE() : this(jclmsCCB2014PINVOKE.new_JCOFFLINE(), true) {
  }

}

}