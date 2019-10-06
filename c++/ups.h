/**
基于udp的可靠传输实现 lougd
2018/06/21
该接口主要实现以下功能：

1.模拟类似tcp send-ack方式保证数据完整性
2.保证封包时序
3.打包自动分包，保证大包传传输效率
*/
#ifndef UPS_SAFE_H_H_
#define UPS_SAFE_H_H_
#include <Windows.h>
#include <vector>
#include <list>
#include <map>
#include <string>
#include "LockBase.h"

using namespace std;

#define MAGIC_NUMBER            0xf1f3              //封包识别数
#define TIMESLICE_STAT          1000                //状态检查时间片
#define PACKET_LIMIT            512                 //单个逻辑包大小限制(根据因特网MTU)
#define MAX_TESTCOUNT           50                  //最多尝试重传次数
#define MAX_RECVTIME            60 * 1000           //接收方丢包最多等待时间
#define MAGIC_SEED              0xeb                //魔数种子
#define PORT_LOCAL_BASE         35001               //本地端口基数
#define BIND_TEST_COUNT         50                  //随机端口尝试次数
#define MAX_SERIAL              64                  //最大封包序号

//操作指令
#define OPT_SEND_DATA           0x0001              //安全数据传送指令
#define OPT_POST_DATA           0x0002              //快速数据传送指令

#define OPT_REQUEST_ACK         0x0011              //数据接收应打包
#define OPT_KEEPALIVE           0x0012              //链接包活包(备用)
#define OPT_KEEPALIVE_ACK       0x0013              //包活包回执

#define MARK_SEND               "send"              //数据发送标识
#define MARK_RECV               "recv"              //数据接收标识

/**
通过类似tcp发送，ack应答的方式保证数据的可靠发送
发送方会在每个时间片内检测是否有回执，如果没有进行数据的重传
为尽可能设计简单，m_uSerial字段仅对OPT_SEND_DATA指令有效
UpsHeader中各个字段通过网络序编码
*/
#pragma pack(1)
struct UpsHeader
{
    unsigned short m_uMagic;       //ups头魔法数
    unsigned short m_uOpt;         //操作指令

    unsigned long m_uSerial;       //封包序号 OPT_SEND:本次发送的封包序号 OPT_ACK:收到封包的序号
    unsigned short m_uSize;        //逻辑包大小 OPT_SEND:本次发送的封包大小 OPT_ACK:收到封包的序号

    UpsHeader() {
    }
};
#pragma pack()

struct PacketSendStat
{
    DWORD m_dwTestCount;

    PacketSendStat()
    {
        m_dwTestCount = 0;
    }
};

struct PacketSendDesc
{
    UpsHeader m_header;
    PacketSendStat m_stat;
    string m_strContent;
};

struct PackageSendCache
{
    string m_strUnique;                 //连接标识
    bool m_bNeedCheckStat;              //是否需要检查状态，所有的包都发送成功就没必要继续检查了
    string m_strRemoteIp;               //远端的地址
    USHORT m_uReomtePort;               //远端的端口
    vector<PacketSendDesc *> m_sendSet; //发送状态缓存

    PackageSendCache()
    {
        m_bNeedCheckStat = false;
        m_uReomtePort = 0;
    }
};

struct PackageInterval
{
    unsigned long m_iStartSerial;
    unsigned long m_iPackageSize;
};

struct PacketRecvDesc
{
    PackageInterval m_interval;             //接收封包序列号
    string m_strContent;                    //接收封包的具体内容
    DWORD m_dwRecvTickCount;                //封包接收的时间
};

struct PackageRecvCache
{
    string m_strUnique;                     //连接标识
    string m_strIp;                         //连接地址
    unsigned short m_uPort;                 //连接端口
    int m_iFirstSerial;                     //第一个序号
    vector<PacketRecvDesc> m_recvDescSet;   //缓冲区中的封包集合
    int m_iSerialGrow;                      //序号增幅，封包序号是1-65536循环使用的，这个参数处理出现循环的情况
    int m_iMagicNum;                        //ups魔法数，用于识别ups封包有效性和是否是同一个session

    PackageRecvCache()
    {
        m_iSerialGrow = 0;
        m_iFirstSerial = -1;
    }
};

struct PackageRecvResult
{
    string m_strIp;
    unsigned short m_uPort;
    string m_strContent;
};

class Ups
{
public:
    Ups();
    virtual ~Ups();

    bool UpsInit(unsigned short uLocalPort, bool bKeepAlive);
    bool UpsConnect(const char *addr, unsigned short uPort, int iTimeOut = 5000);
    bool UpsPost(const char *addr, unsigned short uPort, const char *pData, int iLength);
    bool UpsSend(const char *pData, int iLength);
    int UpsRecv(string &strIp, USHORT &uPort, string &strData);
    bool UpsClose();

protected:
    bool TestBindLocalPort(SOCKET sock, unsigned short uLocalPort);
    bool CheckDataMagic(UpsHeader *header, PackageRecvCache &cache);
    bool PushCompletePacket(PackageRecvCache &cache, const string &strData);
    unsigned short GetMagicNumber();
    bool IsValidMagic(unsigned short uMagic);
    bool SendAck(const char *ip, USHORT uPort, UpsHeader *pHeader);
    bool InsertRecvInterval(PacketRecvDesc desc, vector<PacketRecvDesc> &descSet);
    bool PushCache(PacketSendDesc *desc);
    bool SendToInternal(const string &strIp, USHORT uPort, const string &strData);
    vector<PacketSendDesc *> GetLogicSetFromRawData(const string &strData, int iOpt);
    string GetConnectUnique(const string &ip, unsigned short uPort, const string &strMark);
    bool ClearCacheByResp(string strUnique, UpsHeader header);
    bool OnCheckPacketSendStat();
    bool OnCheckPacketRecvStat();
    bool OnRecvUdpData(const char *addr, unsigned short uPort, const char *pData, int iLength);
    bool OnRecvComplete(PackageRecvCache &recvCache);
    bool OnRecvUpsData(const char *addr, unsigned short uPort, const string &strUnique, UpsHeader *pHeader, const string &strData);
    bool OnRecvUpsAck(const string &strUnique, UpsHeader *pHeader);
    bool OnRecvUpsKeepalive(const char *addr, unsigned short uPort, UpsHeader *pHeader);
    bool OnRecvPostData(const char *addr, unsigned short uPort, UpsHeader *pHeader, const string &strUnique, const string &strData);
    UpsHeader *PacketHeader(unsigned short uOpt, unsigned long uSerial, unsigned short uLength, UpsHeader *ptr);
    UpsHeader *EncodeHeader(UpsHeader *pHeader);
    UpsHeader *DecodeHeader(UpsHeader *pHeader);
    unsigned long GetSendSerial();
    static DWORD WINAPI RecvThread(LPVOID pParam);
    static DWORD WINAPI SendStatThread(LPVOID pParam);
    static DWORD WINAPI RecvStatThread(LPVOID pParam);

protected:
    bool m_bInit;
    bool m_bFirstSend;
    int m_uLocalPort;
    string m_strLocalIp;
    unsigned long m_iSendSerial;
    unsigned short m_uMagicNum;
    SOCKET m_udpSocket;
    HANDLE m_hRecvThread;
    HANDLE m_hSendStatThread;
    HANDLE m_hRecvStatThread;
    HANDLE m_hStatEvent;
    HANDLE m_hStopEvent;
    HANDLE m_hRecvEvent;
    HANDLE m_hSendNotifyEvent;
    HANDLE m_hCurSendWndComplete;
    HANDLE m_hNetActiveEvent;
    bool m_bNetActive;
    string m_strReomteIp;
    unsigned short m_uReomtePort;

    CCriticalSectionLockable m_resultLock;
    CCriticalSectionLockable m_sendLock;
    CCriticalSectionLockable m_recvLock;
    //发送封包缓存
    vector<PacketSendDesc *> m_sendCache;
    //当前的发送窗口
    vector<PacketSendDesc *> m_curSendWnd;

    //接受封包缓存
    map<string, PackageRecvCache> m_recvCache;
    //接收数据结果集
    list<PackageRecvResult> m_result;
};
#endif