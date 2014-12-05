#ifndef jclmsCCB2014_h__
#define jclmsCCB2014_h__
#ifdef  __cplusplus
extern "C" {
#endif
// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 JCLMSCCB2014_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// JCLMSCCB2014_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
//在ARM上使用请打开该宏定义以便消除windows的DLL相关定义的编译错误
//#define _USEON_NONWIN32
#ifndef _WIN32	
//20141203.1709.为了便于ARM移植时减少修改工作量而添加
#define _ZWUSE_AS_JNI
#endif

#ifdef _ZWUSE_AS_JNI
#define JCLMSCCB2014_API
#else
#ifdef JCLMSCCB2014_EXPORTS
#define JCLMSCCB2014_API __declspec(dllexport)
#else
#define JCLMSCCB2014_API __declspec(dllimport)
#endif
#endif //_ZWUSE_AS_JNI



//////////////////////////////////////////////////////////////////////////
extern const int ZW_SYNCALG_BLOCK_SIZE;
extern const int ZW_SM3_DGST_SIZE;

//////////////////////////////////////////////////////////////////////////
typedef enum jc_error_code {
	EJC_SUSSESS,		//成功
	EJC_FAIL,		//失败
	EJC_INPUT_NULL,		//输入条件缺少
	EJC_DATETIME_INVALID,	//日期时间非法
	EJC_VALIDRANGE_INVALID,	//有效期非法
	EJC_CLOSECODE_INVALID,	//闭锁码非法
	EJC_CMDTYPE_TIMESTEP_INVALID,	//时间搜索步长非法
	EJC_CMDTYPE_TIMELEN_INVALID,	//时间搜索长度非法
	EJC_CMDTYPE_INVALID	//命令类型非法
} JCERROR;

typedef enum jc_cmd_type {
	JCCMD_START,		//无效命令
	//初始闭锁码，此时仅有ATM编号，锁编号，PSK三者决定，其余可变因素为定值
	//注意，初始闭锁码的生成，对于每个锁具仅有初始化时仅有一次，所以请仅仅在
	//锁具初始化时生成一次初始闭锁码
	JCCMD_INIT_CLOSECODE,
	JCCMD_CCB_DYPASS1,	//上位机第一开锁密码.此时“闭锁码”字段填写真正的闭锁码
	JCCMD_CCB_LOCK_VERCODE,	//下位机验证码.产生验证码时，“闭锁码”字段必须填写第一开锁密码
	JCCMD_CCB_DYPASS2,	//上位机第二开锁密码.产生第二开锁密码时，“闭锁码”字段填写验证码
	JCCMD_CCB_CLOSECODE,	//生成真正的闭锁码
	JCCMD_RESET_NFCKEY,	//重置NFC钥匙
	JCCMD_RESET_LOCKTIME,	//重设锁体时间
	JCCMD_RESET_LOCKSYSTEM,	//锁系统重置
	JCCMD_GET_LOCKLOG,	//提取锁体日志    
	JCCMD_END
} JCCMD;

typedef enum jc_input_type {
	JCI_START,		//无效值，用于界定上下范围
	JCI_ATMNO,		//ATM编号，初始化时设定
	JCI_LOCKNO,		//锁号，初始化时设定
	JCI_PSK,		//PSK，初始化时设定
	JCI_DATETIME,		//时间日期，单位是秒，应该是GMT秒数
	JCI_VALIDITY,		//有效期，单位是分钟
	JCI_CLOSECODE,		//闭锁码
	JCI_CMDTYPE,		//要生成什么类型的动态码
	JCI_TIMESTEP,		//时间往前推算的间隔，单位为秒
	JCI_SEARCH_TIME_LENGTH,	//反推时间长度，单位为秒，默认值是9分钟(从当前时间的过去6分钟到将来3分钟，适应可能的时间有误差的情形
	JCI_SEARCH_TIME_START,		//搜索时间起始值，默认为当前时间，一般不用设置，主要为了调试和单元测试目的设置。20141118新增；
	JCI_END			//无效值，用于界定上下范围
} JCITYPE;

//离线匹配的返回值
typedef struct jcLockReverseMatchResult {
	int s_datetime;		//匹配结果秒数
	int s_validity;		//匹配结果有效期分钟数
} JCMATCH;


//有效期数组大小；更改此处以后请对应更改源代码中JcLockInput类初始化代码中
//为有效期数组m_validity_array赋予初值的相应语句
#define NUM_VALIDITY (8)
#define JC_ATMNO_MAXLEN (16)	//ATM编号长度最大值
#define JC_LOCKNO_MAXLEN (16)	//LOCK编号长度最大值
#define JC_PSK_LEN (256/4)	//256bit HEX+NULL,这是定长值
#define JC_INVALID_VALUE	(-1)

#pragma pack(1)
typedef struct JcLockInput {
	//固定因素部分
	char AtmNo[JC_ATMNO_MAXLEN + 1];	//ATM号
	char LockNo[JC_LOCKNO_MAXLEN + 1];	//锁号
	char PSK[JC_PSK_LEN + 1];	//PSK，上下位机共同持有的唯一机密因素
	//可变因素部分
	int CodeGenDateTime;		//日期时间
	int Validity;		//有效期
	int CloseCode;	//闭锁码             	
	JCCMD CmdType;	//模式代码，比如开锁模式，远程重置模式，建行的流程要求的各种模式等等
	///////////////////////////////////以下为配置算法运作模式的数据///////////////////////////////////////
	int SearchTimeStart;	//搜索时间起始点，默认值应该是当前时间，但是比如测试时可以额外设定。20141118新增,主要供调试和单元测试使用
	//反推时间步长秒数，默认为在线模式，精度1分钟，值为60，离线模式请自己设置为3600秒或者其他数值
	int SearchTimeStep;
	//往前反推的时间长度秒数，默认为在线模式，10分钟，值为600，其他值比如离线24小时请自己设置
	int SearchTimeLength;
	//有效期，共有NUM_VALIDITY个,默认值是从5分钟到24小时那一系列，单位是分钟；可以自己设定
	//可以把最常用的有效期设置在更靠近开始处加快匹配速度
	int ValidityArray[NUM_VALIDITY];
} JCINPUT;

typedef enum jclmsd_request{
	JCLMS_CCB_CODEGEN,		//动态码生成
	JCLMS_CCB_CODEVERIFY	//动态码反推
}JCLMSOP;

typedef struct jcLmsRequest{
	JCLMSOP Type;
	int dstCode;	//反推运算的输入动态码
	JCINPUT inputData;
}JCLMSREQ;

//用于HID等通信接口返回结果，统一在一个结构体里面
typedef union JcLockResult{
	int dynaCode;			//动态码结果
	JCMATCH verCodeMatch;		//验证码匹配日期时间和有效期结果
}JCRESULT;

#pragma pack()


//分配一个内部数据结构，返回句柄，以后所有操作均以该句柄为对象
int JCLMSCCB2014_API JcLockNew(void);
//删除内部数据结构，释放内存空间，请在所有JCLMS相关代码结束前调用
int JCLMSCCB2014_API JcLockDelete(const int handle);
//设置整数类型的值
JCERROR JCLMSCCB2014_API JcLockSetInt(const int handle, const JCITYPE mtype,
				      int num);
//设置字符串类型的值
JCERROR JCLMSCCB2014_API JcLockSetString(const int handle, const JCITYPE mtype,
					 const char *str);
//设置命令类型(第一开锁码，初始闭锁码等等)
JCERROR JCLMSCCB2014_API JcLockSetCmdType(const int handle, const JCITYPE mtype,
					  const JCCMD cmd);
//检查输入参数合法性
JCERROR JCLMSCCB2014_API JcLockCheckInput(const int handle);
//lock结构体内部m_cmdtype决定了生成哪一类动态码；
int JCLMSCCB2014_API JcLockGetDynaCode(const int handle);
//验证动态码，返回反推出来的时间和有效期结果，失败的话，两者均为0；
JCMATCH JCLMSCCB2014_API JcLockReverseVerifyDynaCode(const int handle,
						     const int dstCode);
//指明该算法是哪一天出的，当算法有运算结果上的变更时这个版本改变，一天最多只出一个版本；
int JCLMSCCB2014_API JcLockGetVersion(void);
//输出调试字符串
void JCLMSCCB2014_API JcLockDebugPrint(const int handle);
void JCLMSCCB2014_API zwJcLockDumpJCINPUT(const int handle);
const int ZWMEGA = 1000000;	//一百万
int JCLMSCCB2014_API zwSM3StandardTestVector(void);
//20141125新增，密盒通信函数,上位机部分
//两个zwJclmsReq函数是上位机专用
//填写完毕handle里面的数据结构以后，调用该函数生成动态码，该函数在底层将请求
//通过HID等通信线路发送到密盒，然后阻塞接收密盒返回结果，通过出参返回；
int JCLMSCCB2014_API zwJclmsReqGenDyCode( int lmsHandle,int *dyCode);
//填写完毕handle里面的数据结构以后，调用该函数验证动态码（第一和第二动态码中间，锁具生成的校验码
//也是使用其他两个动态码的同样算法生成的，所以也算一种动态码，该函数在底层将验证请求通过HID等
//通信线路发送到密盒，然后阻塞接收密盒返回结果，通过出参返回；
int JCLMSCCB2014_API zwJclmsReqVerifyDyCode( int lmsHandle,int dstCode,JCMATCH *match );
int JCLMSCCB2014_API zwLmsAlgStandTest20141203(void);
void JCLMSCCB2014_API zwJclmsRsp( void * inLmsReq,const int inLmsReqLen,JCRESULT *lmsResult );
#ifdef  __cplusplus
}	//extern "C" {
#endif

#endif // jclmsCCB2014_h__
