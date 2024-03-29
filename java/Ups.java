/**
 基于udp的可靠传输实现 lougd
 2018/07/01
 该接口主要实现以下功能：

 1.模拟类似tcp send-ack方式保证数据完整性
 2.保证封包时序
 3.打包自动分包，保证大包传传输效率
 */
package com.example.administrator.dbglibrary;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.concurrent.locks.ReentrantLock;

public class Ups {
    /**
     * Ups数据头
     */
    class UpsHeader {
        int m_iMagic;       //Ups魔法数，用于数据校验和session隔离 实际大小2字节
        int m_iOpt;         //操作指令 实际大小2字节
        long m_iSerial;     //数据序号 实际大小4字节
        int m_iSize;        //数据大小 实际大小2字节
    };

    /**
     * Ups链接
     */
    class UpsConnect {
        String m_strIp = "";
        int m_iPort = 0;
    };

    /**
     * ups对外暴漏的接口
     */
    public boolean UpsInit(int iLocalPort, boolean bKeepAlive) {
        if (m_bInit) {
            return true;
        }

        try {
            m_bInit = true;
            m_iLocalPort = iLocalPort;
            m_clientSocket = new DatagramSocket(m_iLocalPort);

            m_strLocalIp = getLocalIpInternal();
            m_iMagicNumber = getMagicNumber();
            m_bFirstSend = true;
            new RecvDataThread().start();
            new SendDataThread().start();
        } catch (Exception e) {
            String str = e.getMessage();
        }
        return true;
    }

    public boolean UpsConnent(String strIp, int uPort, int iTimeOut) {
        m_strRemoteIp = strIp;
        m_iRemotePort = uPort;

        try {
            long startCount = System.currentTimeMillis();
            UpsHeader header = packetHeader(OPT_KEEPALIVE, 0, 0);
            byte buffer[] = getSendBuffer(header, null);
            while (true) {
                sendToInternal(strIp, uPort, buffer);

                synchronized (m_netActivNotify) {
                    m_netActivNotify.wait(100);
                }

                if (m_bNetActive == true) {
                    return true;
                }

                if (System.currentTimeMillis() - startCount > iTimeOut) {
                    return false;
                }
            }
        } catch (Exception e) {
        }
        return true;
    }

    public boolean UpsPost(String strIp, short uPort, byte data[]) {
        LinkedList<PacketSendDesc> sendSet = getLogicSetFromRawData(data, OPT_SEND_DATA);
        for (PacketSendDesc desc : sendSet) {
            sendToInternal(strIp, uPort, desc.m_content);
        }
        return true;
    }

    public boolean UpsSend(byte data[]) {
        LinkedList<PacketSendDesc> sendSet = getLogicSetFromRawData(data, OPT_SEND_DATA);
        synchronized (m_sendLock) {
            for (PacketSendDesc desc : sendSet) {
                m_sendCache.addLast(desc);
            }
        }

        if (!sendSet.isEmpty()) {
            synchronized (m_sendNotify) {
                m_sendNotify.notify();
            }
        }
        return true;
    }

    class UpsRecvData {
        String m_strIp = "";
        int m_uPort = 0;
        byte m_data[] = null;
    };

    public int UpsRecv(UpsRecvData result) {
        boolean bWait = false;
        try {
            synchronized (m_resultLock) {
                if (m_recvResult.isEmpty()) {
                    bWait = true;
                }
            }

            if (bWait) {
                synchronized (m_recvDataNotify) {
                    m_recvDataNotify.wait();
                }
            }

            synchronized (m_resultLock) {
                if (!m_recvResult.isEmpty()) {
                    PackageRecvResult tmp = m_recvResult.get(0);
                    m_recvResult.remove(0);
                    result.m_strIp = tmp.m_strIp;
                    result.m_uPort = tmp.m_iPort;
                    result.m_data = tmp.m_content;
                    return result.m_data.length;
                }
            }
        } catch (Exception e) {
        }
        return 0;
    }

    /**
     * Usp内部使用的接口
     */
    class RecvDataThread extends Thread {
        public void run() {
            byte buffer[] = new byte[4096];
            while (true) {
                try {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    m_clientSocket.receive(packet);

                    if (packet.getLength() > 0) {
                        byte data[] = new byte[packet.getLength()];
                        System.arraycopy(buffer, 0, data, 0, packet.getLength());
                        onRecvUdpData(packet.getAddress().getHostAddress(), packet.getPort(), data);
                    }
                } catch (Exception e) {
                }
            }
        }
    };

    class SendDataThread extends Thread {
        public void run() {
            while (true) {
                try {
                    synchronized (m_sendNotify) {
                        m_sendNotify.wait(1000);
                    }

                    onSendDataInThread();
                } catch (Exception e) {
                }
            }
        }
    };

    private void onSendDataInThread() {
        while (true) {
            synchronized (m_sendLock) {
                if (m_sendCache.isEmpty()) {
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
                    m_curSendWnd.addLast(m_sendCache.get(0));
                    m_sendCache.remove(0);
                }
            }

            while (true) {
                synchronized (m_sendLock) {
                    for (PacketSendDesc tmp : m_curSendWnd) {
                        sendToInternal(m_strRemoteIp, m_iRemotePort, tmp.m_content);
                    }
                }

                synchronized (m_completeNotify) {
                    try {
                        m_completeNotify.wait(500);
                    } catch (Exception e){
                    }
                }

                synchronized (m_sendLock) {
                    if (m_curSendWnd.isEmpty()) {
                        break;
                    }
                }
            }
        }
    }

    private String getLocalIpInternal() {
        try {
            DatagramSocket tmp = new DatagramSocket();

            InetAddress addr = InetAddress.getByName("1.2.3.4");
            tmp.connect(addr, 7890);
            InetAddress localIp = tmp.getLocalAddress();
            tmp.close();
            return localIp.getHostAddress();
        } catch (Exception e) {
            return "";
        }
    }

    private long getSendSerial() {
        return m_iSendSerial++;
    }

    /**
     * 将原始包封装为一个或者多个框架使用的逻辑包
     */
    private LinkedList<PacketSendDesc> getLogicSetFromRawData(byte data[], int opt) {
        LinkedList<PacketSendDesc> result = new LinkedList<PacketSendDesc>();
        int iPos = 0;
        int iUseSize = 0;
        final int iRealSize = (MAX_PACKETSIZE - HEADER_SIZE);

        while (true) {
            if (iPos >= data.length) {
                break;
            }

            if (data.length - iUseSize < iRealSize) {
                break;
            }

            long iSerial = 0;
            if (opt == OPT_SEND_DATA) {
                iSerial = getSendSerial();
            }
            UpsHeader header = packetHeader(opt, iSerial, iRealSize);
            PacketSendDesc desc = new PacketSendDesc();
            desc.m_header = header;

            byte subData[] = new byte[iRealSize];
            System.arraycopy(data, iPos, subData, 0, iRealSize);
            desc.m_content = getSendBuffer(header, subData);
            result.addLast(desc);
            iPos += iRealSize;
            iUseSize += iRealSize;
        }

        if (iPos < data.length) {
            long iSerial = 0;
            if (opt == OPT_SEND_DATA) {
                iSerial = getSendSerial();
            }

            UpsHeader header = packetHeader(opt, iSerial, data.length - iPos);
            PacketSendDesc desc = new PacketSendDesc();
            desc.m_header = header;
            byte subData[] = new byte[data.length - iPos];
            System.arraycopy(data, iPos, subData, 0, data.length - iPos);
            desc.m_content = getSendBuffer(header, subData);
            result.addLast(desc);
        }
        return result;
    }

    private String getConnectUnique(String strIp, int iPort, String strMark) {
        return String.format("%s_%d-%s_%d_%s", strIp, iPort, m_strLocalIp, m_iLocalPort, strMark);
    }

    private byte[] getSendBuffer(UpsHeader header, byte userData[]) {
        int iSize = HEADER_SIZE;
        if (userData != null && userData.length > 0) {
            iSize += userData.length;
        }

        byte buffer[] = new byte[iSize];
        byte tmp[] = null;
        tmp = ushortToByteArry(header.m_iMagic);
        System.arraycopy(tmp, 0, buffer, 0, 2);
        tmp = ushortToByteArry(header.m_iOpt);
        System.arraycopy(tmp, 0, buffer, 2, 2);
        tmp = uintToByteArry(header.m_iSerial);
        System.arraycopy(tmp, 0, buffer, 4, 4);
        tmp = ushortToByteArry(header.m_iSize);
        System.arraycopy(tmp, 0, buffer, 8, 2);

        if (userData != null && userData.length > 0) {
            System.arraycopy(userData, 0, buffer, HEADER_SIZE, userData.length);
        }
        return buffer;
    }

    private UpsHeader packetHeader(int iOpt, long iSerial, int iSize) {
        UpsHeader header = new UpsHeader();
        header.m_iMagic = m_iMagicNumber;
        header.m_iOpt = iOpt;
        header.m_iSize = iSize;
        header.m_iSerial = iSerial;
        return header;
    }

    private int getMagicNumber() {
        long s = System.currentTimeMillis();
        int high = ((int)s & 0xff);
        int low = ((high ^ MAGIC_SEED) & 0xff);
        return ((high << 8) | low);
    }

    private boolean sendAck(String strIp, int iPort, UpsHeader recvHeader) {
        UpsHeader ackHeader = packetHeader(OPT_REQUEST_ACK, recvHeader.m_iSerial, recvHeader.m_iSize);
        sendToInternal(strIp, iPort, getSendBuffer(ackHeader, null));
        return true;
    }

    /**
     * 将结果追加到完成列表中
     */
    private boolean pushCompletePacket(PackageRecvCache cache, byte userData[]) {
        PackageRecvResult result = new PackageRecvResult();
        result.m_strIp = cache.m_strIp;
        result.m_iPort = cache.m_iPort;
        result.m_content = userData;

        synchronized (m_resultLock) {
            m_recvResult.addLast(result);
        }
        m_recvDataNotify.notify();
        return true;
    }

    /**
     * 检查session是否发生变化
     */
    private boolean checkSession(UpsHeader recvHeader, PackageRecvCache cache) {
        if (recvHeader.m_iMagic != cache.m_iMagicNum) {
            for (PackageRecvDesc desc : cache.m_recvDescSet) {
                pushCompletePacket(cache, desc.m_content);
            }

            cache.m_recvDescSet.clear();
            cache.m_iMagicNum = recvHeader.m_iMagic;
            cache.m_iFirstSerial = 0;
        }
        return true;
    }

    private boolean insertRecvInterval(PackageRecvDesc desc, LinkedList<PackageRecvDesc> descSet) {
        int i = 0;
        for (PackageRecvDesc tmp : descSet) {
            if (desc.m_iStartSerial < tmp.m_iStartSerial) {
                descSet.add(i, tmp);
                return true;
            }

            if (desc.m_iStartSerial == tmp.m_iStartSerial) {
                return false;
            }
            i++;
        }
        descSet.addLast(desc);
        return true;
    }

    private boolean onRecvComplete(PackageRecvCache recvCache) {
        int i = 0;
        while (i != recvCache.m_recvDescSet.size()) {
            PackageRecvDesc desc = recvCache.m_recvDescSet.get(i);
            if (recvCache.m_iFirstSerial == desc.m_iStartSerial) {
                recvCache.m_iFirstSerial++;
                recvCache.m_recvDescSet.remove(i);
                pushCompletePacket(recvCache, desc.m_content);
            } else {
                break;
            }
        }
        return true;
    }

    /**
     * 远端发来的数据包
     */
    private boolean onRecvUpsSendData(String strIp, int iPort, UpsHeader recvHeader, byte buffer[]) {
        sendAck(strIp, iPort, recvHeader);
        String strUnique = getConnectUnique(strIp, iPort, MARK_RECV);

        if (!m_recvCache.containsKey(strUnique)) {
            PackageRecvCache cache = new PackageRecvCache();
            cache.m_strUnique = strUnique;
            cache.m_strIp = strIp;
            cache.m_iPort = iPort;
            cache.m_iFirstSerial = recvHeader.m_iSerial;
            cache.m_iMagicNum = recvHeader.m_iMagic;
            m_recvCache.put(strUnique, cache);
        }

        PackageRecvCache recvCache = m_recvCache.get(strUnique);
        checkSession(recvHeader, recvCache);

        if (recvHeader.m_iSerial < recvCache.m_iFirstSerial) {
            return true;
        }

        PackageRecvDesc curDesc = new PackageRecvDesc();
        curDesc.m_iRecvTickCount = System.currentTimeMillis();
        curDesc.m_iStartSerial = recvHeader.m_iSerial;
        curDesc.m_iPackageSize = recvHeader.m_iSize;

        curDesc.m_content = new byte[buffer.length - HEADER_SIZE];
        System.arraycopy(buffer, HEADER_SIZE, curDesc.m_content, 0, buffer.length - HEADER_SIZE);
        insertRecvInterval(curDesc, recvCache.m_recvDescSet);
        onRecvComplete(recvCache);
        return true;
    }

    private boolean onRecvUpsPostData(String strIp, int iPort, UpsHeader recvHeader, byte data[]) {
        String strUnique = getConnectUnique(strIp, iPort, MARK_RECV);

        if (!m_recvCache.containsKey(strUnique)) {
            PackageRecvCache cache = new PackageRecvCache();
            cache.m_strUnique = strUnique;
            cache.m_strIp = strIp;
            cache.m_iPort = iPort;
            cache.m_iFirstSerial = recvHeader.m_iSerial;
            cache.m_iMagicNum = recvHeader.m_iMagic;
            m_recvCache.put(strUnique, cache);
        }

        PackageRecvCache recvCache = m_recvCache.get(strUnique);
        byte userData[] = new byte[data.length - HEADER_SIZE];
        System.arraycopy(data, HEADER_SIZE, userData, 0, data.length - HEADER_SIZE);
        pushCompletePacket(recvCache, userData);
        return true;
    }

    private boolean onRecvUpsAck(String strIp, int iPort, UpsHeader recvHeader) {
        int i = 0;
        synchronized (m_sendLock) {
            while (i != m_curSendWnd.size()) {
                PacketSendDesc desc = m_curSendWnd.get(i);
                if (recvHeader.m_iSerial == desc.m_header.m_iSerial) {
                    m_curSendWnd.remove(i);
                    break;
                }
                i++;
            }

            if (m_curSendWnd.isEmpty()) {
                synchronized (m_completeNotify) {
                    m_completeNotify.notify();
                }
            }
            return true;
        }
    }

    private boolean onRecvUpsKeeplive(String strIP, int iPort, UpsHeader recvHeader) {
        UpsHeader ackHeader = packetHeader(OPT_KEEPALIVE_ACK, 0, 0);
        byte data[] = getSendBuffer(ackHeader, null);
        sendToInternal(strIP, iPort, data);
        return true;
    }

    private boolean onRecvKeepliveAck(String strIp, int iPort, UpsHeader header) {
        synchronized (m_netActivNotify) {
            m_netActivNotify.notify();
            m_bNetActive = true;
        }
        return true;
    }

    private boolean onRecvUdpData(String strIp, int iPort, byte buffer[]) {
        UpsHeader header = new UpsHeader();
        if (!parserUpsData(buffer, header)) {
            return false;
        }

        if (buffer.length != (header.m_iSize + HEADER_SIZE)) {
            return false;
        }

        if (!isValidMagic(header.m_iMagic)) {
            return false;
        }

        switch (header.m_iOpt) {
            case OPT_SEND_DATA:
                onRecvUpsSendData(strIp, iPort, header, buffer);
                break;
            case OPT_POST_DATA:
                onRecvUpsPostData(strIp, iPort, header, buffer);
                break;
            case OPT_REQUEST_ACK:
                onRecvUpsAck(strIp, iPort, header);
                break;
            case OPT_KEEPALIVE:
                onRecvUpsKeeplive(strIp, iPort, header);
                break;
            case OPT_KEEPALIVE_ACK:
                onRecvKeepliveAck(strIp, iPort, header);
                break;
            default:
                break;
        }
        return true;
    }

    private boolean sendToInternal(String strIp, int iPort, byte data[]) {
        try {
            DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName(strIp), iPort);

            m_clientSocket.send(packet);
        } catch (Exception e) {
        }
        return true;
    }

    private boolean isValidMagic(int uMagic) {
        int iHight = ((uMagic >> 8) & 0xff);
        int iLow = (uMagic & 0xff);
        return (iLow == ((iHight ^ MAGIC_SEED) & 0xff));
    }

    private boolean parserUpsData(byte buffer[], UpsHeader header) {
        if (buffer.length < HEADER_SIZE) {
            return false;
        }

        header.m_iMagic = byteArryToUshort(buffer);
        byte sub[] = new byte[4];
        System.arraycopy(buffer, 2, sub, 0, 2);
        header.m_iOpt = byteArryToUshort(sub);
        System.arraycopy(buffer, 4, sub, 0, 4);
        header.m_iSerial = byteArryToUint(sub);
        System.arraycopy(buffer, 8, sub, 0, 2);
        header.m_iSize = byteArryToUshort(sub);
        return true;
    }

    /**
     * java字节序是大端(网络序)，获取到的网络数据不再需要转换
     * 以下是字节码到整形与整形到字节码的转换接口
     */
    private int byteArryToUshort(byte b[]) {
        return ((b[0] & 0xff) << 8) | (b[1] & 0xff);
    }

    private long byteArryToUint(byte b[]) {
        long result = 0;
        for (int i = 0 ; i < 4 ; i++) {
            result |= ((b[3 - i] & 0xff) << (i * 8));
        }
        return result;
    }

    private byte[] ushortToByteArry(int i) {
        byte b[] = new byte[2];
        b[0] = (byte)((i >> 8) & 0xff);
        b[1] = (byte)(i & 0xff);
        return b;
    }

    private byte[] uintToByteArry(long a) {
        byte b[] = new byte[4];
        for (int i = 0 ; i < 4 ; i++) {
            b[3 - i] = (byte)((a >> i * 8) & 0xff);
        }
        return b;
    }

    /**
     * 数据接收缓存
     */
    class PackageRecvDesc {
        long m_iStartSerial = 0;
        long m_iPackageSize = 0;

        byte m_content[] = null;
        long m_iRecvTickCount = 0;
    };

    class PackageRecvCache {
        String m_strUnique = "";
        String m_strIp = "";
        int m_iPort = 0;
        long m_iFirstSerial = 0;
        LinkedList<PackageRecvDesc> m_recvDescSet = new LinkedList<>();
        int m_iMagicNum = 0;
    };

    class PackageRecvResult {
        String m_strIp = "";
        int m_iPort = 0;
        byte m_content[] = null;
    };

    /**
     * 数据发送缓存
     */
    class PacketSendDesc {
        UpsHeader m_header = new UpsHeader();
        int m_iTestCount = 0;
        byte m_content[] = null;
    };

    private final int OPT_SEND_DATA    = 0x0001;
    private final int OPT_POST_DATA    = 0x0002;
    private final int OPT_REQUEST_ACK  = 0x0011;
    private final int OPT_KEEPALIVE    = 0x0012;
    private final int OPT_KEEPALIVE_ACK= 0x0013;
    private final int MAX_PACKETSIZE   = 512;

    private final String MARK_SEND = "send";
    private final String MARK_RECV = "recv";

    private final int HEADER_SIZE = 10;             //ups头大小
    private final int MAGIC_SEED = 0xeb;            //魔数种子
    private int m_iMagicNumber = 0;
    private DatagramSocket m_clientSocket = null;
    private String m_strLocalIp = null;
    private int m_iLocalPort = 0;
    private String m_strRemoteIp = null;
    private int m_iRemotePort = 0;
    private boolean m_bNetActive = false;
    private long m_iSendSerial = 0;
    private boolean m_bFirstSend = true;

    private HashMap<String, PackageRecvCache> m_recvCache = new HashMap<String, PackageRecvCache>();
    private LinkedList<PackageRecvResult> m_recvResult = new LinkedList<PackageRecvResult>();

    private LinkedList<PacketSendDesc> m_sendCache = new LinkedList<PacketSendDesc>();
    private LinkedList<PacketSendDesc> m_curSendWnd = new LinkedList<PacketSendDesc>();
    private ReentrantLock m_sendLock = new ReentrantLock();
    private ReentrantLock m_recvLock = new ReentrantLock();
    private ReentrantLock m_resultLock = new ReentrantLock();
    private ReentrantLock m_completeNotify = new ReentrantLock();
    private ReentrantLock m_netActivNotify = new ReentrantLock();
    private ReentrantLock m_sendNotify = new ReentrantLock();
    private ReentrantLock m_recvDataNotify = new ReentrantLock();
    private ReentrantLock m_stopNotify = new ReentrantLock();
    private boolean m_bInit = false;
}
