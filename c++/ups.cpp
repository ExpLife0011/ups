#include <WinSock2.h>
#include <gdcharconv.h>
#include "ups.h"

Ups::Ups()
{
    m_bInit = false;
    m_uLocalPort = 0;
    m_iSendSerial = 0;
    m_udpSocket = INVALID_SOCKET;
    m_hRecvThread = NULL;
    m_hSendStatThread = NULL;
    m_hRecvStatThread = NULL;
    m_uMagicNum = 0;
    m_bNetActive = false;
    m_hSendNotifyEvent = NULL;
    m_bFirstSend = true;
}

Ups::~Ups()
{}

string Ups::GetConnectUnique(const string &ip, unsigned short uPort, const string &strMark)
{
    return fmt("%hs_%d-%d_%hs", ip.c_str(), uPort, m_uLocalPort, strMark.c_str());
}

bool Ups::InsertRecvInterval(PacketRecvDesc desc, vector<PacketRecvDesc> &descSet)
{
    vector<PacketRecvDesc>::const_iterator it;
    for (it = descSet.begin() ; it != descSet.end() ; it++)
    {
        if (desc.m_interval.m_iStartSerial < it->m_interval.m_iStartSerial)
        {
            descSet.insert(it, desc);
            return true;
        }
        //封包发送重复
        else if (desc.m_interval.m_iStartSerial == it->m_interval.m_iStartSerial)
        {
            return false;
        }
    }

    if (it == descSet.end())
    {
        descSet.push_back(desc);
    }
    return true;
}

unsigned short Ups::GetMagicNumber()
{
    DWORD dw = GetTickCount();
    unsigned short hight = (dw & 0xff);
    unsigned short low = (hight ^ MAGIC_SEED);
    unsigned short uMagic = ((hight << 8) | low);
    return uMagic;
}

bool Ups::IsValidMagic(unsigned short uMagic)
{
    unsigned short hight = ((uMagic >> 8) & 0xff);
    unsigned short low = (uMagic & 0xff);
    return (low == ((hight ^ MAGIC_SEED) & 0xff));
}

bool Ups::SendAck(const char *ip, USHORT uPort, UpsHeader *pHeader)
{
    UpsHeader ack;
    PacketHeader(OPT_REQUEST_ACK, pHeader->m_uSerial, 0, &ack);
    return SendToInternal(ip, uPort, string((const char *)&ack, sizeof(ack)));
}

bool Ups::OnRecvComplete(PackageRecvCache &recvCache)
{
    int iCount = 0;
    vector<PacketRecvDesc> interval = recvCache.m_recvDescSet;
    for (vector<PacketRecvDesc>::iterator ij = interval.begin() ; ij != interval.end() ; ij++, iCount++)
    {
        if (ij->m_interval.m_iStartSerial == recvCache.m_iFirstSerial)
        {
            recvCache.m_iFirstSerial++;
            PushCompletePacket(recvCache, ij->m_strContent);
        }
        else
        {
            break;
        }
    }

    if (iCount > 0)
    {
        recvCache.m_recvDescSet.erase(recvCache.m_recvDescSet.begin(), recvCache.m_recvDescSet.begin() + iCount);
    }
    return true;
}

bool Ups::CheckDataMagic(UpsHeader *header, PackageRecvCache &cache)
{
    CScopedLocker lock(&m_recvLock);
    if (header->m_uMagic != cache.m_iMagicNum)
    {
        for (vector<PacketRecvDesc>::iterator it = cache.m_recvDescSet.begin() ; it != cache.m_recvDescSet.end() ; it++)
        {
            PushCompletePacket(cache, it->m_strContent);
        }
        cache.m_recvDescSet.clear();
        cache.m_iFirstSerial = header->m_uSerial;
        cache.m_iMagicNum = header->m_uMagic;
        cache.m_iSerialGrow = 0;
    }
    return true;
}

bool Ups::PushCompletePacket(PackageRecvCache &cache, const string &strData)
{
    CScopedLocker lock(&m_resultLock);
    PackageRecvResult result;
    result.m_strIp = cache.m_strIp;
    result.m_uPort = cache.m_uPort;
    result.m_strContent = strData;
    m_result.push_back(result);

    SetEvent(m_hRecvEvent);
    return true;
}

bool Ups::OnRecvUpsData(const char *addr, unsigned short uPort, const string &strUnique, UpsHeader *pHeader, const string &strData)
{
    CScopedLocker lock(&m_recvLock);
    map<string, PackageRecvCache>::iterator it;
    if (m_recvCache.end() == (it = m_recvCache.find(strUnique)))
    {
        PackageRecvCache cache;
        cache.m_strUnique = strUnique;
        cache.m_strIp = addr;
        cache.m_uPort = uPort;
        cache.m_iFirstSerial = pHeader->m_uSerial;
        cache.m_iMagicNum = pHeader->m_uMagic;
        m_recvCache[strUnique] = cache;
        it = m_recvCache.find(strUnique);
    }

    //session是否发生变化
    CheckDataMagic(pHeader, it->second);

    int iCurSerial = (pHeader->m_uSerial);
    if (iCurSerial < it->second.m_iFirstSerial)
    {
        return true;
    }

    PacketRecvDesc desc;
    desc.m_dwRecvTickCount = GetTickCount();
    PackageInterval interval;
    interval.m_iStartSerial = iCurSerial;
    interval.m_iPackageSize = pHeader->m_uSize;
    desc.m_interval = interval;
    desc.m_strContent = strData;
    //将封包区间插入区间集合，等待之前的封包接收
    InsertRecvInterval(desc, it->second.m_recvDescSet);
    OnRecvComplete(it->second);
    return true;
}

bool Ups::OnRecvUpsAck(const string &strUnique, UpsHeader *pHeader)
{
    CScopedLocker lock(&m_sendLock);
    //检查当前数据窗口的封包的接收情况
    for (vector<PacketSendDesc *>::iterator it = m_curSendWnd.begin() ; it != m_curSendWnd.end() ;)
    {
        PacketSendDesc *pDesc = *it;
        if (pHeader->m_uSerial == pDesc->m_header.m_uSerial)
        {
            m_curSendWnd.erase(it);
            break;
        }
        else
        {
            it++;
        }
    }

    if (m_curSendWnd.empty())
    {
        SetEvent(m_hCurSendWndComplete);
    }
    return true;
}

UpsHeader *Ups::EncodeHeader(UpsHeader *pHeader)
{
    pHeader->m_uMagic = htons(pHeader->m_uMagic);
    pHeader->m_uOpt = htons(pHeader->m_uOpt);
    pHeader->m_uSerial = htonl(pHeader->m_uSerial);
    pHeader->m_uSize = htons(pHeader->m_uSize);
    return pHeader;
}

UpsHeader *Ups::DecodeHeader(UpsHeader *pHeader)
{
    pHeader->m_uMagic = ntohs(pHeader->m_uMagic);
    pHeader->m_uOpt = ntohs(pHeader->m_uOpt);
    pHeader->m_uSerial = ntohl(pHeader->m_uSerial);
    pHeader->m_uSize = ntohs(pHeader->m_uSize);
    return pHeader;
}

bool Ups::OnRecvPostData(const char *addr, unsigned short uPort, UpsHeader *pHeader, const string &strUnique, const string &strData)
{
    CScopedLocker lock(&m_recvLock);
    map<string, PackageRecvCache>::iterator it;
    if (m_recvCache.end() == (it = m_recvCache.find(strUnique)))
    {
        PackageRecvCache cache;
        cache.m_strIp = addr;
        cache.m_uPort = uPort;
        cache.m_iMagicNum = pHeader->m_uMagic;
        cache.m_strUnique = strUnique;
        m_recvCache[strUnique] = cache;
        it = m_recvCache.find(strUnique);
    }

    PushCompletePacket(it->second, strData);
    return true;
}

UpsHeader *Ups::PacketHeader(unsigned short uOpt, unsigned long uSerial, unsigned short uLength, UpsHeader *ptr)
{
    ptr->m_uMagic = m_uMagicNum;
    ptr->m_uOpt = uOpt;
    ptr->m_uSerial = uSerial;
    ptr->m_uSize = uLength;
    return EncodeHeader(ptr);
}

bool Ups::OnRecvUpsKeepalive(const char *addr, unsigned short uPort, UpsHeader *pHeader)
{
    if (pHeader->m_uMagic == m_uMagicNum)
    {
        SetEvent(m_hNetActiveEvent);
    }

    UpsHeader header;
    PacketHeader(OPT_KEEPALIVE_ACK, 0, 0, &header);
    SendToInternal(addr, uPort, string((const char *)&header, sizeof(header)));
    return true;
}

bool Ups::OnRecvUdpData(const char *addr, unsigned short uPort, const char *pData, int iLength)
 {
    UpsHeader header;
    memcpy(&header, pData, sizeof(header));
    DecodeHeader(&header);

    if (!IsValidMagic(header.m_uMagic))
    {
        return false;
    }

    if (iLength != (header.m_uSize + sizeof(UpsHeader)))
    {
        return false;
    }

    string strUnique;
    int iDataLength = iLength - sizeof(UpsHeader);
    switch (header.m_uOpt) {
        case OPT_SEND_DATA:
            {
                strUnique = GetConnectUnique(addr, uPort, MARK_RECV);
                /**
                map<string, PackageRecvCache>::iterator it;
                if (m_recvCache.end() != (it = m_recvCache.find(strUnique)))
                {
                    string dbg = fmt("recv data3:%d\n", header.m_uSerial + it->second.m_iSerialGrow);
                    OutputDebugStringA(dbg.c_str());
                }
                */
                SendAck(addr, uPort, &header);
                OnRecvUpsData(addr, uPort, strUnique, &header, string(pData + sizeof(UpsHeader), iDataLength));
            }
            break;
        case OPT_POST_DATA:
            {
                strUnique = GetConnectUnique(addr, uPort, MARK_RECV);
                OnRecvPostData(addr, uPort, &header, strUnique, string(pData + sizeof(UpsHeader), iDataLength));
            }
            break;
        case OPT_REQUEST_ACK:
            {
                strUnique = GetConnectUnique(addr, uPort, MARK_SEND);
                OnRecvUpsAck(strUnique, &header);
            }
            break;
        case OPT_KEEPALIVE:
            {
                OnRecvUpsKeepalive(addr, uPort, &header);
            }
            break;
        case OPT_KEEPALIVE_ACK:
            break;
        default:
            break;
    }
    return true;
}

DWORD Ups::RecvThread(LPVOID pParam)
{
    Ups *ptr = (Ups *)pParam;
    char buffer[4096];
    int iBufferSize = sizeof(buffer);
    SOCKADDR_IN clientAddr = {0};
    int iAddrSize = sizeof(clientAddr);

    while (true)
    {
        iAddrSize = sizeof(clientAddr);
        int iRecvSize = recvfrom(ptr->m_udpSocket, buffer, iBufferSize, 0, (sockaddr *)&clientAddr, &iAddrSize);

        if (iRecvSize <= 0)
        {
            break;
        }

        if(iRecvSize < sizeof(UpsHeader))
        {
            continue;
        }

        string strAddr = inet_ntoa(clientAddr.sin_addr);
        USHORT uPort = ntohs(clientAddr.sin_port);
        ptr->OnRecvUdpData(strAddr.c_str(), uPort, buffer, iRecvSize);
    }
    return 0;
}

bool Ups::SendToInternal(const string &strIp, USHORT uPort, const string &strData)
{
    SOCKADDR_IN addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.S_un.S_addr = inet_addr(strIp.c_str());
    addr.sin_port = htons(uPort);
    sendto(m_udpSocket, strData.c_str(), strData.length(), 0, (const sockaddr *)&addr, sizeof(addr));
    return true;
}

bool Ups::OnCheckPacketSendStat()
{
    while (true)
    {
        {
            CScopedLocker lock(&m_sendLock);
            if (m_sendCache.empty())
            {
                break;
            }

            /**
            用一组数据制作一个数据窗口，循环发送数据并等待个窗口数据发送完成
            */
            int iWndCount = 0;
            if (m_bFirstSend)
            {
                m_bFirstSend = false;
                iWndCount = 1;
            }
            else
            {
                iWndCount = 25;
            }

            /**
            首次发送可能会发生先收到第2个或者第3个包，这会导致首个包收不到
            通过单独发送首个包规避这个问题。
            */
            for (int i = 0 ; i < iWndCount && m_sendCache.size() > 0; i++)
            {
                vector<PacketSendDesc *>::iterator it = m_sendCache.begin();
                m_curSendWnd.push_back(*it);
                m_sendCache.erase(it);
            }
        }

        while (true)
        {
            {
                CScopedLocker lock(&m_sendLock);
                vector<PacketSendDesc *>::const_iterator it;
                for (it = m_curSendWnd.begin() ; it != m_curSendWnd.end() ; it++)
                {
                    PacketSendDesc *pDesc = *it;
                    SendToInternal(m_strReomteIp, m_uReomtePort, pDesc->m_strContent);
                }
            }

            DWORD dwResult = WaitForSingleObject(m_hCurSendWndComplete, 500);
            if (m_curSendWnd.empty())
            {
                break;
            }
        }
    }
    return true;
}

bool Ups::OnCheckPacketRecvStat()
{
    CScopedLocker lock(&m_recvLock);
    DWORD dwCurCount = GetTickCount();
    for (map<string, PackageRecvCache>::iterator it = m_recvCache.begin() ; it != m_recvCache.end() ; it++)
    {
        if (it->second.m_recvDescSet.size() > 0 && ((dwCurCount - it->second.m_recvDescSet.begin()->m_dwRecvTickCount) > MAX_RECVTIME))
        {
            it->second.m_iFirstSerial = it->second.m_recvDescSet.begin()->m_interval.m_iStartSerial;
            OnRecvComplete(it->second);
        }
    }
    return true;
}

unsigned long Ups::GetSendSerial()
{
    return m_iSendSerial++;
}

vector<PacketSendDesc *> Ups::GetLogicSetFromRawData(const string &strData, int opt)
{
    int iPos = 0;
    vector<PacketSendDesc *> result;
    int iRealSize = (PACKET_LIMIT - sizeof(UpsHeader));
    int iFreeSize = strData.size();
    while (true)
    {
        if (iPos >= (int)strData.size())
        {
            break;
        }

        if (iFreeSize <= 0)
        {
            break;
        }

        if (iFreeSize <= iRealSize)
        {
            break;
        }

        PacketSendDesc *ptr = new PacketSendDesc();
        if (opt == OPT_SEND_DATA)
        {
            PacketHeader(opt, GetSendSerial(), iRealSize, &(ptr->m_header));
        }
        else
        {
            PacketHeader(opt, 0, iRealSize, &(ptr->m_header));
        }
        ptr->m_strContent.append((const char *)(&(ptr->m_header)), sizeof(UpsHeader));
        ptr->m_strContent += strData.substr(iPos, iRealSize);
        DecodeHeader(&(ptr->m_header));
        result.push_back(ptr);

        iPos += iRealSize;
        iFreeSize -= iRealSize;
    }

    if (iPos < (int)strData.size())
    {
        PacketSendDesc *ptr = new PacketSendDesc();
        unsigned short uSize = strData.size() - iPos;

        if (opt == OPT_SEND_DATA)
        {
            PacketHeader(opt, GetSendSerial(), uSize, &(ptr->m_header));
        }
        else
        {
            PacketHeader(opt, 0, uSize, &(ptr->m_header));
        }
        ptr->m_strContent.append((const char *)(&(ptr->m_header)), sizeof(UpsHeader));
        ptr->m_strContent += strData.substr(iPos, strData.size() - iPos);
        DecodeHeader(&(ptr->m_header));
        result.push_back(ptr);
    }
    return result;
}

DWORD Ups::SendStatThread(LPVOID pParam)
{
    Ups *ptr = (Ups *)pParam;
    HANDLE arry[] = {ptr->m_hSendNotifyEvent, ptr->m_hStopEvent};
    while (true)
    {
        DWORD dwRet = WaitForMultipleObjects(RTL_NUMBER_OF(arry), arry, FALSE, TIMESLICE_STAT);

        if ((WAIT_OBJECT_0 + 1) == dwRet)
        {
            break;
        }
        ptr->OnCheckPacketSendStat();
    }
    return 0;
}

DWORD Ups::RecvStatThread(LPVOID pParam)
{
    Ups *ptr = (Ups *)pParam;
    while (true)
    {
        DWORD dwRet = WaitForSingleObject(ptr->m_hStopEvent, TIMESLICE_STAT);

        if ((WAIT_OBJECT_0 + 1) == dwRet)
        {
            break;
        }
        //ptr->OnCheckPacketRecvStat();
    }
    return 0;
}

bool Ups::TestBindLocalPort(SOCKET sock, unsigned short uLocalPort)
{
    SOCKADDR_IN localAddr = {0};
    localAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(uLocalPort);
    if (-1 == bind(m_udpSocket, (sockaddr *)&localAddr, sizeof(localAddr)))
    {
        return false;
    }
    return true;
}

bool Ups::UpsInit(unsigned short uLocalPort, bool bKeepAlive)
{
    if (m_bInit)
    {
        return false;
    }

    m_udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    m_uLocalPort = uLocalPort;

    if (uLocalPort > 0)
    {
        if (!TestBindLocalPort(m_udpSocket, uLocalPort))
        {
            closesocket(m_udpSocket);
            m_udpSocket = INVALID_SOCKET;
            return false;
        }
    }
    else
    {
        /**
        udp特性决定随机端口也需要在接收数据前先绑定一个端口或则先发送一条数据
        否则在该socket上调用recvfrom会失败
        */
        int i = 0;
        for (i = 0 ; i < BIND_TEST_COUNT ; i++)
        {
            if (TestBindLocalPort(m_udpSocket, PORT_LOCAL_BASE + i))
            {
                m_uLocalPort = PORT_LOCAL_BASE + i;
                break;
            }
        }

        if (BIND_TEST_COUNT == i)
        {
            closesocket(m_udpSocket);
            m_udpSocket = INVALID_SOCKET;
            return false;
        }
    }

    m_bInit = true;
    m_bFirstSend = true;
    int nRecvBuf = 50 * 1024 * 1024;
    int res = setsockopt(m_udpSocket, SOL_SOCKET, SO_RCVBUF, (const char *)&nRecvBuf,sizeof(nRecvBuf));

    m_uMagicNum = GetMagicNumber();
    m_hStatEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    m_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    m_hRecvEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    m_hCurSendWndComplete = CreateEventW(NULL, FALSE, FALSE, NULL);
    m_hSendNotifyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    m_hNetActiveEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    m_hRecvThread = CreateThread(NULL, 0, RecvThread, this, 0, NULL);
    m_hSendStatThread = CreateThread(NULL, 0, SendStatThread, this, 0, NULL);
    m_hRecvStatThread = CreateThread(NULL, 0, RecvStatThread, this, 0, NULL);
    return true;
}

bool Ups::UpsConnect(const char *addr, unsigned short uPort, int iTimeOut)
{
    m_strReomteIp = addr;
    m_uReomtePort = uPort;
    UpsHeader header;
    PacketHeader(OPT_KEEPALIVE, 0, 0, &header);

    DWORD dwStartCount = GetTickCount();
    while(true) {
        SendToInternal(m_strReomteIp, m_uReomtePort, string((const char *)&header, sizeof(header)));
        if (WAIT_OBJECT_0 == WaitForSingleObject(m_hNetActiveEvent, 100))
        {
            return true;
        }

        if (GetTickCount() - dwStartCount >= (DWORD)iTimeOut)
        {
            return false;
        }
    }
    return false;
}

bool Ups::UpsClose()
{
    if (!m_bInit)
    {
        return false;
    }

    m_bInit = false;
    closesocket(m_udpSocket);
    m_udpSocket = INVALID_SOCKET;
    SetEvent(m_hStopEvent);
    CloseHandle(m_hStopEvent);
    CloseHandle(m_hStatEvent);
    CloseHandle(m_hRecvEvent);
    m_hStopEvent = NULL;
    m_hStatEvent = NULL;
    m_hRecvEvent = NULL;

    CloseHandle(m_hSendStatThread);
    CloseHandle(m_hRecvStatThread);
    m_hSendStatThread = NULL;
    m_hRecvStatThread = NULL;
    CloseHandle(m_hNetActiveEvent);
    CloseHandle(m_hSendNotifyEvent);
    CloseHandle(m_hCurSendWndComplete);
    m_hNetActiveEvent = NULL;
    m_hSendNotifyEvent = NULL;
    m_hCurSendWndComplete = NULL;
    m_bFirstSend = true;
    return true;
}

bool Ups::UpsPost(const char *addr, unsigned short uPort, const char *pData, int iLength)
{
    vector<PacketSendDesc *> result = GetLogicSetFromRawData(string(pData, iLength), OPT_POST_DATA);
    for (vector<PacketSendDesc *>::iterator it = result.begin() ; it != result.end() ; it++)
    {
        PacketSendDesc *ptr = *it;
        SendToInternal(addr, uPort, ptr->m_strContent);
    }
    return true;
}

bool Ups::PushCache(PacketSendDesc *desc)
{
    m_sendCache.push_back(desc);
    return true;
}

bool Ups::UpsSend(const char *pData, int iLength)
{
    vector<PacketSendDesc *> result = GetLogicSetFromRawData(string(pData, iLength), OPT_SEND_DATA);
    for (vector<PacketSendDesc *>::iterator it = result.begin() ; it != result.end() ; it++)
    {
        PacketSendDesc *ptr = *it;
        {
            CScopedLocker lock(&m_sendLock);
            PushCache(ptr);
            SetEvent(m_hSendNotifyEvent);
        }
    }
    return true;
}

int Ups::UpsRecv(string &strIp, USHORT &uPort, string &strData)
{
    WaitForSingleObject(m_hRecvEvent, INFINITE);
    CScopedLocker lock(&m_resultLock);
    if (m_result.size() > 0)
    {
        PackageRecvResult result = *m_result.begin();
        m_result.pop_front();
        if (m_result.empty())
        {
            ResetEvent(m_hRecvEvent);
        }

        strIp = result.m_strIp;
        uPort = result.m_uPort;
        strData = result.m_strContent;
        return strData.size();
    }
    return 0;
}