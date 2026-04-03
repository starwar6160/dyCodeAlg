# dyCodeAlg
动态密码生成算法
我负责设计一种电子动态密码锁的密码生成算法，并把该算法移植到ARM Cortex M3；该算法根据指定的人员ID，使用时间，地点，有效期等要素，
动态生成一个8位数字，使用一次后作废。
我负责了该算法的设计，C++/golang编码实现，移植到ARM，客户现场调试等全部过程；

Dynamic password generation algorithm
I am responsible for designing a password generation algorithm for an electronic dynamic password lock and porting the algorithm to ARM Cortex M3; the algorithm generates an 8-digit number dynamically based on the specified person ID, time of use, location, expiration date, and other elements.
The algorithm dynamically generates an 8-digit number that is invalidated after one use.
I was responsible for the design of the algorithm, C++/golang coding implementation, porting to ARM, and customer site debugging.

---

### Tech Archaeology: 2015 Source Code vs. Modern DLT (BBc-1 Protocol)
**English Info**: This project is an offline security scheme designed for bank safes in 2015. The core hash-chain state machine and offline validation mechanism implemented here on an 8-bit MCU intrinsically pre-evaluated and foreshadowed the architecture of modern decentralized ledger technologies, particularly the non-global consensus models like the BBc-1 (Beyond Blockchain One) protocol. See `/docs/Technical_Whitepaper_2015_vs_BBc1.md` for a detailed cryptographic architecture analysis.

**日本語紹介**: 本プロジェクトは2015年に銀行のオフライン金庫向けに設計されたセキュリティスキーマです。ここで実装された8ビットMCU上での「ハッシュチェーン状態マシン」や「オフライン検証機構」は、BBc-1（Beyond Blockchain One）プロトコルのような現代の非グローバル・コンセンサス型・分散型台帳（DLT）のアーキテクチャやトランザクショントポロジと本質的に合致・先行予演していました。詳細な暗号化アーキテクチャの対比については `/docs/Technical_Whitepaper_2015_vs_BBc1.md`をご参照ください。
