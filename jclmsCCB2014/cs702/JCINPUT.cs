/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

namespace jclms {

public class JCINPUT : global::System.IDisposable {
  private global::System.Runtime.InteropServices.HandleRef swigCPtr;
  protected bool swigCMemOwn;

  internal JCINPUT(global::System.IntPtr cPtr, bool cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = new global::System.Runtime.InteropServices.HandleRef(this, cPtr);
  }

  internal static global::System.Runtime.InteropServices.HandleRef getCPtr(JCINPUT obj) {
    return (obj == null) ? new global::System.Runtime.InteropServices.HandleRef(null, global::System.IntPtr.Zero) : obj.swigCPtr;
  }

  ~JCINPUT() {
    Dispose();
  }

  public virtual void Dispose() {
    lock(this) {
      if (swigCPtr.Handle != global::System.IntPtr.Zero) {
        if (swigCMemOwn) {
          swigCMemOwn = false;
          jclmsCCB2014PINVOKE.delete_JCINPUT(swigCPtr);
        }
        swigCPtr = new global::System.Runtime.InteropServices.HandleRef(null, global::System.IntPtr.Zero);
      }
      global::System.GC.SuppressFinalize(this);
    }
  }

  public string m_atmno {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_atmno_set(swigCPtr, value);
    } 
    get {
      string ret = jclmsCCB2014PINVOKE.JCINPUT_m_atmno_get(swigCPtr);
      return ret;
    } 
  }

  public string m_lockno {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_lockno_set(swigCPtr, value);
    } 
    get {
      string ret = jclmsCCB2014PINVOKE.JCINPUT_m_lockno_get(swigCPtr);
      return ret;
    } 
  }

  public string m_psk {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_psk_set(swigCPtr, value);
    } 
    get {
      string ret = jclmsCCB2014PINVOKE.JCINPUT_m_psk_get(swigCPtr);
      return ret;
    } 
  }

  public int m_datetime {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_datetime_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JCINPUT_m_datetime_get(swigCPtr);
      return ret;
    } 
  }

  public int m_validity {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_validity_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JCINPUT_m_validity_get(swigCPtr);
      return ret;
    } 
  }

  public int m_closecode {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_closecode_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JCINPUT_m_closecode_get(swigCPtr);
      return ret;
    } 
  }

  public JCCMD m_cmdtype {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_cmdtype_set(swigCPtr, (int)value);
    } 
    get {
      JCCMD ret = (JCCMD)jclmsCCB2014PINVOKE.JCINPUT_m_cmdtype_get(swigCPtr);
      return ret;
    } 
  }

  public int m_stepoftime {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_stepoftime_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JCINPUT_m_stepoftime_get(swigCPtr);
      return ret;
    } 
  }

  public int m_reverse_time_length {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_reverse_time_length_set(swigCPtr, value);
    } 
    get {
      int ret = jclmsCCB2014PINVOKE.JCINPUT_m_reverse_time_length_get(swigCPtr);
      return ret;
    } 
  }

  public SWIGTYPE_p_int m_validity_array {
    set {
      jclmsCCB2014PINVOKE.JCINPUT_m_validity_array_set(swigCPtr, SWIGTYPE_p_int.getCPtr(value));
    } 
    get {
      global::System.IntPtr cPtr = jclmsCCB2014PINVOKE.JCINPUT_m_validity_array_get(swigCPtr);
      SWIGTYPE_p_int ret = (cPtr == global::System.IntPtr.Zero) ? null : new SWIGTYPE_p_int(cPtr, false);
      return ret;
    } 
  }

  public JCINPUT() : this(jclmsCCB2014PINVOKE.new_JCINPUT(), true) {
  }

}

}
