# GitHub 库 `starwar6160/dyCodeAlg` 核心逻辑深度分析报告

作为高级密码学与逆向工程专家，在对 `dyCodeAlg` 核心 C++ 源文件（主要是 `zwAlgCommCode/jclmsCCB2014AlgCore.cpp` 和相配套的头文件）进行深入分析后，整理出以下基于源代码的算法演变与依赖关系报告。

---

## 1. 状态依赖性：密码学依赖链设计

通过分析 `jclmsCCB2014AlgCore.h` 中定义的 `JCCMD` 枚举体以及源文件中的 `JcLockSetCmdType`、`embSrvGenDyCode` 逻辑流程不难发现，该算法设计了包含上下级多轮互动的“哈希链”。

**闭锁码 (Close Code) 在全过程中的角色设定与传递过程及密码学依赖链：**

*   **前置状态：历史闭锁码** 
    通过上一次开闭锁流程或系统初始化（`JCCMD_INIT_CLOSECODE`）生成，该密码或作为状态变量存入设备内部（`CloseCode`）。
*   **第 1 环：生成第一开锁码 (DYPASS1)** 
    上位机发送申请开锁时，算法使用 `JCCMD_CCB_DYPASS1` 命令，此时函数的 `CloseCode` 字段填写真正的**设备上的当前闭锁码**。
*   **第 2 环：生成锁体验证码 (VERCODE)**
    锁具（下位机）收到第一开锁码后，将其作为种子变量。算法使用 `JCCMD_CCB_LOCK_VERCODE` 时，`CloseCode` 字段被**替换为刚才的第一开锁码**。
*   **第 3 环：生成第二开锁码 (DYPASS2)** 
    上位机接收到锁具返回的验证码后，将其作为种子，使用 `JCCMD_CCB_DYPASS2` 时，`CloseCode` 字段**填入该验证码**以生成真正的第二开锁命令发给锁具。
*   **第 4 环：更新闭锁码 (CLOSECODE)** 
    开锁成功/超时/关闭事件发生时，通过 `JCCMD_CCB_CLOSECODE` 生成新的闭锁码。这里的种子是一组默认的盐值，并覆盖到状态机中。

**哈希链抽象：**
`Pre_CloseCode -> HASH(Pre_CloseCode + ...) -> DYPASS1 -> HASH(DYPASS1 + ...) -> VERCODE -> HASH(VERCODE + ...) -> DYPASS2`。 这种层层递推构成了前向/后向安全性，如果上一层不正确，下一层的动态口令绝对无法生成。

---

## 2. 非对称验证逻辑：无实时同步的离线 HASH

锁具端通常处于离线环境，如何与上位机匹配授权是一大难点。代码在防篡改的基础上采用了类似于 TOTP (Time-based One-Time Password) 但是更复杂的穷举反推验证（Reverse Verification）设计。

**具体验证逻辑（引自 `JcLockReverseVerifyDynaCode` 函数）：**
1.  **因子收集**：验证的输入基包括：ATM号 (`AtmNo`)、锁号 (`LockNo`)、预共享密钥 (`PSK`)。这三者与每次不断演化的 `CloseCode` 一起决定了唯一性。
2.  **抗时钟漂移策略**：在没有网络实时同步的极端情况下，设备的内部时钟可能跑快或跑慢。代码中定义了时间容差策略 `JC_DCODE_MATCH_FUTURE_SEC = 60 * 3`（代表未来 3 分钟）。
3.  **多维碰撞搜索**：下位机会从 `当前时间 + 3分钟` 开始逆向时间轴 `tdate -= l_timestep`（步长通常被规格化为 6 秒），并行遍历所有的可能有效期 `NUM_VALIDITY`（5分钟，15分钟直到24小时）。在循环内部通过 SM3 将 `时间`、`有效期` 和 `各种因子` HASH 一遍，并比对运算获取的 8 位密码。一旦匹配，即视为认证通过同时校准设备内部时间。

---

## 3. 防重放与防中间人：基于“上一次成功状态”的校验

在 `jclmsCCB2014AlgCore.cpp` 源码中，防重放（Anti-Replay）深度结合在了 SM3 HMAC 的哈希状态混淆内。该算法没有依赖传统的随机数 Nonce，而是依赖时间与递进序列。

**代码行证：** 
在 `zwJcLockGetDynaCode()` 生成密码逻辑中，以下语句直接阻断了重放攻击：

```cpp
// 601行左右: 首先处理固定字段的HASH值输入
mySM3Update(&sm3, jcp->AtmNo, sizeof(jcp->AtmNo));
mySM3Update(&sm3, jcp->LockNo, sizeof(jcp->LockNo));
mySM3Update(&sm3, jcp->PSK, sizeof(jcp->PSK));

// 605行左右: 继续输入各个可变字段的HASH值
mySM3Update(&sm3, l_datetime);      // 动态时间拦截老旧重放报文
mySM3Update(&sm3, l_validity);
mySM3Update(&sm3, l_closecode);     // 截断中间人的核心：包含上一个成功状态闭锁码
mySM3Update(&sm3, jcp->CmdType);    // 命令隔离：第一密码绝对不会与校验码发生碰撞
...
SM3_Final(&sm3, (char *)(outHmac));
```

**机制说明：**
*   **抗重放**：`l_datetime` (时间因子) 的硬性掺入保证了老旧抓包的口令会因为时效衰减而无法在锁具端穷举范围内碰撞成功。
*   **防中间人 (MITM)**：必须知道上一次有效通讯生成的口令（作为新的 `l_closecode` 输入）。中间人如果仅仅拦截网络请求，并试图发送伪造的 `DYPASS2`，那么由于其并非合法的上一轮推导体，锁具利用自己缓存的合法上一次状态去参与 HASH 校验时会导致哈希雪崩效应，立刻全盘决绝。

---

## 4. 资源约束优化（8-bit MCU与内存环境优化）

由于在极小内存 MCU 等低功耗设备中运行，代码展现出了为资源妥协的专项优化。

*   **大步长整数离差分析**：
    `myGetNormalTime` (第74行) 依靠整型向下取整技巧 `int tail = gmtTime % TIMEMOD; return gmtTime - tail;` 直接对时钟戳执行按时间分片单位（例如6秒步长）的截断抹平。这种抹平手段砍掉了时间精细对齐所需的无用穷举次数。
*   **非对称穷举数组优先序**（命中率优化）：
    有效期并非无极递增变量，代码定义常数 `NUM_VALIDITY (8)`。在 `JcLockNew()` 内分配了特定索引：`pjc->ValidityArray[0] = 5; pjc->ValidityArray[1] = 60 * 4; ...` 由于绝大多数操作使用的是“5分钟”有效期，将其放在优先首位，MCU 可以在大多数情况下仅进行一次内层校验就 `goto foundMatch;` (`720` 行)，节省电量与周期。
*   **哈希折叠提取算法** (`zwBinString2Int32` 函数，214行)：
    要从 32 字节长的 SM3 输出提取一次性 8 位单向安全密码：
    ```cpp
    const int dyLow = 10000019;       // 八位质数底线
    const int dyMod = 89999969;       // 取模控制位
    const int dyMul = 257;            // 乘数因子
    
    unsigned __int64 sum = 0;
    // 乘法混合移位：
    for (int i = 0; i < len; i++) {
        unsigned char t = *(data + i);
        sum *= dyMul;
        sum += t; 
    }
    sum %= dyMod;
    sum += dyLow;
    return static_cast<unsigned int>(sum);
    ```
    它利用质数底线 (`dyLow`)、掩码基 (`dyMod`)、步进乘数 (`dyMul = 257`) 替代了大整数或字符串操作，所有算法仅用 64 bit 无符号整数基础位移乘法完成，避免了 sprintf 等耗资源操作，最后输出绝对在 `10000019 - 99999988` 这一安全的 8 位数区间。这在极小的资源约束下，用极少代码取得了非常均一的映射分布。
