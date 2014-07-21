/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

namespace jclms {

public class JcLockInput : global::System.IDisposable {
  private global::System.Runtime.InteropServices.HandleRef swigCPtr;
  protected bool swigCMemOwn;

  internal JcLockInput(global::System.IntPtr cPtr, bool cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = new global::System.Runtime.InteropServices.HandleRef(this, cPtr);
  }

  internal static global::System.Runtime.InteropServices.HandleRef getCPtr(JcLockInput obj) {
    return (obj == null) ? new global::System.Runtime.InteropServices.HandleRef(null, global::System.IntPtr.Zero) : obj.swigCPtr;
  }

  ~JcLockInput() {
    Dispose();
  }

  public virtual void Dispose() {
    lock(this) {
      if (swigCPtr.Handle != global::System.IntPtr.Zero) {
        if (swigCMemOwn) {
          swigCMemOwn = false;
          jclmsCCB2014PINVOKE.delete_JcLockInput(swigCPtr);
        }
        swigCPtr = new global::System.Runtime.InteropServices.HandleRef(null, global::System.IntPtr.Zero);
      }
      global::System.GC.SuppressFinalize(this);
    }
  }

  public string m_atmno {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_atmno_set(swigCPtr, value);
      if (jclmsCCB2014PINVOKE.SWIGPendingException.Pending) throw jclmsCCB2014PINVOKE.SWIGPendingException.Retrieve();
    } 
    get {
      string ret = jclmsCCB2014PINVOKE.JcLockInput_m_atmno_get(swigCPtr);
      if (jclmsCCB2014PINVOKE.SWIGPendingException.Pending) throw jclmsCCB2014PINVOKE.SWIGPendingException.Retrieve();
      return ret;
    } 
  }

  public string m_lockno {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_lockno_set(swigCPtr, value);
      if (jclmsCCB2014PINVOKE.SWIGPendingException.Pending) throw jclmsCCB2014PINVOKE.SWIGPendingException.Retrieve();
    } 
    get {
      string ret = jclmsCCB2014PINVOKE.JcLockInput_m_lockno_get(swigCPtr);
      if (jclmsCCB2014PINVOKE.SWIGPendingException.Pending) throw jclmsCCB2014PINVOKE.SWIGPendingException.Retrieve();
      return ret;
    } 
  }

  public string m_psk {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_psk_set(swigCPtr, value);
      if (jclmsCCB2014PINVOKE.SWIGPendingException.Pending) throw jclmsCCB2014PINVOKE.SWIGPendingException.Retrieve();
    } 
    get {
      string ret = jclmsCCB2014PINVOKE.JcLockInput_m_psk_get(swigCPtr);
      if (jclmsCCB2014PINVOKE.SWIGPendingException.Pending) throw jclmsCCB2014PINVOKE.SWIGPendingException.Retrieve();
      return ret;
    } 
  }

  public int m_datetime {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_datetime_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JcLockInput_m_datetime_get(swigCPtr);
      return ret;
    } 
  }

  public int m_validity {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_validity_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JcLockInput_m_validity_get(swigCPtr);
      return ret;
    } 
  }

  public int m_closecode {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_closecode_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JcLockInput_m_closecode_get(swigCPtr);
      return ret;
    } 
  }

  public JCCMD m_cmdtype {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_cmdtype_set(swigCPtr, (int)value);
    } 
    get {
      JCCMD ret = (JCCMD)jclmsCCB2014PINVOKE.JcLockInput_m_cmdtype_get(swigCPtr);
      return ret;
    } 
  }

  public int m_stepoftime {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_stepoftime_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JcLockInput_m_stepoftime_get(swigCPtr);
      return ret;
    } 
  }

  public int m_reverse_time_length {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_reverse_time_length_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JcLockInput_m_reverse_time_length_get(swigCPtr);
      return ret;
    } 
  }

  public SWIGTYPE_p_int m_validity_array {
    set {
      jclmsCCB2014PINVOKE.JcLockInput_m_validity_array_set(swigCPtr, SWIGTYPE_p_int.getCPtr(value));
    } 
    get {
      global::System.IntPtr cPtr = jclmsCCB2014PINVOKE.JcLockInput_m_validity_array_get(swigCPtr);
      SWIGTYPE_p_int ret = (cPtr == global::System.IntPtr.Zero) ? null : new SWIGTYPE_p_int(cPtr, false);
      return ret;
    } 
  }

  public JcLockInput() : this(jclmsCCB2014PINVOKE.new_JcLockInput(), true) {
  }

  public void DebugPrint() {
    jclmsCCB2014PINVOKE.JcLockInput_DebugPrint(swigCPtr);
  }

  public JCERROR CheckInput() {
    JCERROR ret = (JCERROR)jclmsCCB2014PINVOKE.JcLockInput_CheckInput(swigCPtr);
    return ret;
  }

  public void SetValidity(int index, int val) {
    jclmsCCB2014PINVOKE.JcLockInput_SetValidity(swigCPtr, index, val);
  }

}

}
