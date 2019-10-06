/**
����udp�Ŀɿ�����ʵ�� lougd
2018/06/21
�ýӿ���Ҫʵ�����¹��ܣ�

1.ģ������tcp send-ack��ʽ��֤����������
2.��֤���ʱ��
3.����Զ��ְ�����֤���������Ч��
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

#define MAGIC_NUMBER            0xf1f3              //���ʶ����
#define TIMESLICE_STAT          1000                //״̬���ʱ��Ƭ
#define PACKET_LIMIT            512                 //�����߼�����С����(����������MTU)
#define MAX_TESTCOUNT           50                  //��ೢ���ش�����
#define MAX_RECVTIME            60 * 1000           //���շ��������ȴ�ʱ��
#define MAGIC_SEED              0xeb                //ħ������
#define PORT_LOCAL_BASE         35001               //���ض˿ڻ���
#define BIND_TEST_COUNT         50                  //����˿ڳ��Դ���
#define MAX_SERIAL              64                  //��������

//����ָ��
#define OPT_SEND_DATA           0x0001              //��ȫ���ݴ���ָ��
#define OPT_POST_DATA           0x0002              //�������ݴ���ָ��

#define OPT_REQUEST_ACK         0x0011              //���ݽ���Ӧ���
#define OPT_KEEPALIVE           0x0012              //���Ӱ����(����)
#define OPT_KEEPALIVE_ACK       0x0013              //�������ִ

#define MARK_SEND               "send"              //���ݷ��ͱ�ʶ
#define MARK_RECV               "recv"              //���ݽ��ձ�ʶ

/**
ͨ������tcp���ͣ�ackӦ��ķ�ʽ��֤���ݵĿɿ�����
���ͷ�����ÿ��ʱ��Ƭ�ڼ���Ƿ��л�ִ�����û�н������ݵ��ش�
Ϊ��������Ƽ򵥣�m_uSerial�ֶν���OPT_SEND_DATAָ����Ч
UpsHeader�и����ֶ�ͨ�����������
*/
#pragma pack(1)
struct UpsHeader
{
    unsigned short m_uMagic;       //upsͷħ����
    unsigned short m_uOpt;         //����ָ��

    unsigned long m_uSerial;       //������ OPT_SEND:���η��͵ķ����� OPT_ACK:�յ���������
    unsigned short m_uSize;        //�߼�����С OPT_SEND:���η��͵ķ����С OPT_ACK:�յ���������

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
    string m_strUnique;                 //���ӱ�ʶ
    bool m_bNeedCheckStat;              //�Ƿ���Ҫ���״̬�����еİ������ͳɹ���û��Ҫ���������
    string m_strRemoteIp;               //Զ�˵ĵ�ַ
    USHORT m_uReomtePort;               //Զ�˵Ķ˿�
    vector<PacketSendDesc *> m_sendSet; //����״̬����

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
    PackageInterval m_interval;             //���շ�����к�
    string m_strContent;                    //���շ���ľ�������
    DWORD m_dwRecvTickCount;                //������յ�ʱ��
};

struct PackageRecvCache
{
    string m_strUnique;                     //���ӱ�ʶ
    string m_strIp;                         //���ӵ�ַ
    unsigned short m_uPort;                 //���Ӷ˿�
    int m_iFirstSerial;                     //��һ�����
    vector<PacketRecvDesc> m_recvDescSet;   //�������еķ������
    int m_iSerialGrow;                      //�����������������1-65536ѭ��ʹ�õģ���������������ѭ�������
    int m_iMagicNum;                        //upsħ����������ʶ��ups�����Ч�Ժ��Ƿ���ͬһ��session

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
    //���ͷ������
    vector<PacketSendDesc *> m_sendCache;
    //��ǰ�ķ��ʹ���
    vector<PacketSendDesc *> m_curSendWnd;

    //���ܷ������
    map<string, PackageRecvCache> m_recvCache;
    //�������ݽ����
    list<PackageRecvResult> m_result;
};
#endif