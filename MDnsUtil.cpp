#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string>
#include <sstream>
#include <vector>
#include <chrono>

#include "MDnsUtil.h"

void print_buf(const uint8_t* ptr, int size)
{
	for (int i = 0; i < size; i++) {
		printf("%02x ", ptr[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
}

typedef struct mdns_header_s {
    uint16_t ID;
    uint16_t FLAGS;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
} mdns_header_t;

typedef struct mdns_question_s {
    std::string QNAME;
    uint16_t QTYPE;
    uint16_t QCLASS;
} mdns_question_t;

typedef struct mdns_rr_s {
    std::string NAME;
    uint16_t TYPE;
    uint16_t CLASS;
    uint32_t TTL;
    std::string RDATA;
} mdns_rr_t;

typedef struct mdns_response_s {
    struct sockaddr_in peer;
    mdns_header_t header;
    std::vector<mdns_question_t> question;
    std::vector<mdns_rr_t> answer;
    std::vector<mdns_rr_t> authority;
    std::vector<mdns_rr_t> addition;    
} mdns_response_t;

class Buffer
{
public:
    Buffer();
    void SetBuffer(uint8_t* buf, int size);
    uint8_t ReadUint8();
    uint16_t ReadUint16();
    uint32_t ReadUint32();
    void WriteUint8(uint8_t val);
    void WriteUint16(uint16_t val);
    void WriteUint32(uint32_t val);
    void WriteBuffer(uint8_t* buf, int size);
    
    void Skip(int len);
    uint8_t* GetCurrent();
    uint8_t* GetBase();
    int GetRemain();
    int GetLength();
    int GetMaxSize();
    
private:
    uint8_t* mData;
    int mIndex;
    int mMaxSize;
};

Buffer::Buffer()
{
    mData = NULL;
    mMaxSize = 0;
    mIndex = 0;
}

void Buffer::SetBuffer(uint8_t* buf, int size)
{
    mData = buf;
    mIndex = 0;
    mMaxSize = size;
}

uint8_t Buffer::ReadUint8()
{
    uint8_t val;
    
    val = mData[mIndex];
    mIndex++;
    
    return val;
}

uint16_t Buffer::ReadUint16()
{
    uint16_t val;
    
    memcpy(&val, mData + mIndex, 2);
    mIndex += 2;
    
    return ntohs(val);    
}

uint32_t Buffer::ReadUint32()
{
    uint32_t val;
    
    memcpy(&val, mData + mIndex, 4);
    mIndex += 4;
    
    return ntohl(val);      
}

void Buffer::WriteUint8(uint8_t val)
{
    mData[mIndex] = val;
    mIndex += 1;
}

void Buffer::WriteUint16(uint16_t val)
{
    val = htons(val);
    memcpy(mData + mIndex, &val, 2);
    mIndex += 2; 
}

void Buffer::WriteUint32(uint32_t val)
{
    val = htonl(val);
    memcpy(mData + mIndex, &val, 4);
    mIndex += 4;     
}

void Buffer::WriteBuffer(uint8_t* buf, int size)
{
    memcpy(mData + mIndex, buf, size);
    mIndex += size;
}

void Buffer::Skip(int len)
{
    mIndex += len;
}

uint8_t* Buffer::GetCurrent()
{
    return mData + mIndex;
}

uint8_t* Buffer::GetBase()
{
    return mData;
}

int Buffer::GetRemain()
{
    return mMaxSize - mIndex;
}

int Buffer::GetLength()
{
    return mIndex;
}

int Buffer::GetMaxSize()
{
    return mMaxSize;
}

class MDnsUtilImpl
{
public:
    MDnsUtilImpl();
    bool Resolve(std::string service, int scanTime);
    std::vector<mdns_service_t>& GetServices();
    
private:
    void BuildQuery(std::string& query, std::string service);
    bool ParseResponse(mdns_response_t& resp, uint8_t* data, int size);
    bool ParseResponseHeader(mdns_response_t& resp, Buffer& buf);
    bool ParseQuestion(mdns_response_t& resp, Buffer& buf);
    bool ParseAnswer(mdns_response_t& resp, Buffer& buf);
    bool ParseAuthority(mdns_response_t& resp, Buffer& buf);
    bool ParseAddition(mdns_response_t& resp, Buffer& buf);
    bool ParseRR(Buffer& buf, std::vector<mdns_rr_t>& rrv);
    bool ParseSrvRR();
    bool ReadName(Buffer& buf, std::string& name);
    bool ReadLabelSeq(Buffer& buf, std::string& name, int offset);
    void WriteName(Buffer& buf, std::string& name);

private:
    int CreateSocket();
    int Send(int fd, int port, const uint8_t* buf, int len);
    int Recv(int fd, uint8_t* buff, int len, struct sockaddr_in* peer);

private:
    Buffer mBuffer;
    
    std::vector<mdns_response_t> mResponses;
    std::vector<mdns_service_t> mServices;
};

MDnsUtilImpl::MDnsUtilImpl()
{
    
}

bool MDnsUtilImpl::ParseResponse(mdns_response_t& resp, uint8_t* data, int size)
{
    Buffer buf;
    buf.SetBuffer(data, size);
    
    if (!ParseResponseHeader(resp, buf)) {
        printf("header error\n");
        return false;
    }
    
    if (!ParseQuestion(resp, buf)) {
        printf("question error\n");
        return false;
    }
    
    if (!ParseAnswer(resp, buf)) {
        printf("answer error\n");
        return false;
    }
    
    if (!ParseAuthority(resp, buf)) {
        printf("authority error\n");
        return false;
    }
    
    if (!ParseAddition(resp, buf)) {
        printf("addition error\n");
        return false;
    }
    
    return true;
}

bool MDnsUtilImpl::ParseResponseHeader(mdns_response_t& resp, Buffer& buf)
{
    resp.header.ID = buf.ReadUint16();
    resp.header.FLAGS = buf.ReadUint16();
    resp.header.QDCOUNT = buf.ReadUint16();
    resp.header.ANCOUNT = buf.ReadUint16();
    resp.header.NSCOUNT = buf.ReadUint16();
    resp.header.ARCOUNT = buf.ReadUint16();

    if ((resp.header.FLAGS & 0x8000) == 0)
        return false;
    
    return true;
}

bool MDnsUtilImpl::ParseQuestion(mdns_response_t& resp, Buffer& buf)
{
    for (int i = 0; i < resp.header.QDCOUNT; i++) {
        mdns_question_t q;
 
        if (!ReadName(buf, q.QNAME))
            return false;
        
        q.QTYPE = buf.ReadUint16();
        q.QCLASS = buf.ReadUint16();
        
        resp.question.push_back(q);
    }
    
    return true;
}

bool MDnsUtilImpl::ParseRR(Buffer& buf, std::vector<mdns_rr_t>& rrv)
{
    mdns_rr_t rr;
    int rdlen;
    
    if (!ReadName(buf, rr.NAME))
        return false;
    
    rr.TYPE = buf.ReadUint16();
    rr.CLASS = buf.ReadUint16();
    rr.TTL = buf.ReadUint32();
    
    rdlen = buf.ReadUint16();
    
    if (buf.GetRemain() < rdlen)
        return false;
    
    rr.RDATA.append((const char*)buf.GetCurrent(), rdlen);
    buf.Skip(rdlen);
    
    rrv.push_back(rr);
    
    return true;
}

bool MDnsUtilImpl::ParseAnswer(mdns_response_t& resp, Buffer& buf)
{
    for (int i = 0; i < resp.header.ANCOUNT; i++) {
        if (!ParseRR(buf, resp.answer))
            return false;
    }
    
    return true;
}

bool MDnsUtilImpl::ParseAuthority(mdns_response_t& resp, Buffer& buf)
{
    for (int i = 0; i < resp.header.NSCOUNT; i++) {
        if (!ParseRR(buf, resp.authority))
            return false;
    }
    
    return true;    
}

bool MDnsUtilImpl::ParseAddition(mdns_response_t& resp, Buffer& buf)
{
    for (int i = 0; i < resp.header.ARCOUNT; i++) {
        if (!ParseRR(buf, resp.addition))
            return false;
    }
    
    return true;       
}

bool MDnsUtilImpl::ReadLabelSeq(Buffer& buf, std::string& name, int offset)
{
    Buffer tmp;
    tmp.SetBuffer(buf.GetBase() + offset, buf.GetMaxSize() - offset);
    
    while(true) {
        uint8_t len = tmp.ReadUint8();
        
        if (len == 0)
            return true;
        
        if ((len & 0xc0) == 0xc0) {
            //label seq end with pointer
            int off = ((len & 0x3f) << 8) | tmp.ReadUint8();
            if (tmp.GetRemain() <= 0)
                return false;
            
            return ReadLabelSeq(buf, name, off);
        } else {
            if (tmp.GetRemain() <= 0)
                return false;
            
            name.append((const char*)tmp.GetCurrent(), len);
            name.append(".");
            
            tmp.Skip(len);
        }
    }
    
    return true;
}

bool MDnsUtilImpl::ReadName(Buffer& buf, std::string& name)
{
    //https://www.ietf.org/rfc/rfc1035.txt
    //4.1.4. Message compression
    while(true) {
        uint8_t len = buf.ReadUint8();
        
        if (len == 0)
            return true;
        
        if ((len & 0xc0) == 0xc0) {
            int offset = ((len & 0x3f) << 8) | buf.ReadUint8();
            return ReadLabelSeq(buf, name, offset);
        } else {
            if (buf.GetRemain() <= 0)
                return false;
            
            name.append((const char*)buf.GetCurrent(), len);
            name.append(".");

            buf.Skip(len);
        }
    }
    
    return true;
}

void MDnsUtilImpl::WriteName(Buffer& buf, std::string& name)
{
    std::vector<std::string> strs;
    std::istringstream iss(name);
    
    std::string s;
    while (std::getline(iss, s, '.')) {
        strs.push_back(s);
    }
    
    for (int i = 0; i < strs.size(); i++) {
        buf.WriteUint8(strs[i].length());
        buf.WriteBuffer((uint8_t*)strs[i].c_str(), strs[i].length());
    }
    
    buf.WriteUint8(0);
}

bool MDnsUtilImpl::ParseSrvRR()
{
    for (int i = 0; i < mResponses.size(); i++) {
        mdns_response_t& resp = mResponses[i];
        
        for (int j = 0; j < resp.addition.size(); j++) {
            if (resp.addition[j].TYPE != 33)
                continue;
            
            Buffer buf;
            buf.SetBuffer((uint8_t*)resp.addition[j].RDATA.c_str(), resp.addition[j].RDATA.length());
            
            mdns_service_t srv;
            srv.host = inet_ntoa(resp.peer.sin_addr);
            srv.name = resp.addition[j].NAME;
            
            buf.ReadUint16(); //priority
            buf.ReadUint16(); //weight
            
            srv.port = buf.ReadUint16();

            mServices.push_back(srv);
        }
    }
    
    return true;
}

void MDnsUtilImpl::BuildQuery(std::string& query, std::string service)
{
    Buffer buf;
    uint8_t data[1480];
    
    buf.SetBuffer(data, sizeof(data));
    
    buf.WriteUint16(0); //ID
    buf.WriteUint16(0); //flags
    buf.WriteUint16(1); //QDCOUNT
    buf.WriteUint16(0); //ANCOUNT
    buf.WriteUint16(0); //NSCOUNT
    buf.WriteUint16(0); //ARCOUNT;
    
    WriteName(buf, service);
    
    buf.WriteUint16(0x000c); //QTYPE
    buf.WriteUint16(0x0001); //QCLASS
    
    query.append((const char*)buf.GetBase(), buf.GetLength());
}

bool MDnsUtilImpl::Resolve(std::string service, int scanTime)
{
    std::string query;
    uint8_t data[1480];
    int fd, n;
    bool res = false;
    std::chrono::system_clock::time_point start;
    
    BuildQuery(query, service);

    fd = CreateSocket();
    if (fd < 0)
        return false;
    
    n = Send(fd, 5353, (const uint8_t*)query.c_str(), query.length());
    if (n < 0)
        goto error;
    
    start = std::chrono::system_clock::now();
    while(1) {
        auto now = std::chrono::system_clock::now();
        if (now - start > std::chrono::seconds(scanTime))
            break;
        
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        timeval tv = {0};
        tv.tv_sec = static_cast<long>(scanTime);

        int st = select(fd+1, &fds, nullptr, nullptr, &tv);

        if (st < 0) {
            printf("Failed to wait on socket with code: %s", strerror(errno));
            return false; 
        }

        if (st > 0) {
            mdns_response_t resp;
            
            n = Recv(fd, data, sizeof(data), &(resp.peer));
            if (n < 0)
                goto error;
            
            if (!ParseResponse(resp, data, n))
                goto error;
            
            mResponses.push_back(resp);
        }
    }
    
    if (!ParseSrvRR()) {
        printf("service rr error\n");
        goto error;      
    }
    
    res = true;
error:
    
    close(fd);
    return res;
}

int MDnsUtilImpl::CreateSocket()
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("failed to create socket\n");
        return -1;
    }
    
    int val = 1;
    int res = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (const char*)&val, sizeof(val));
    
    if (res < 0) {
        close(fd);
    }
    
    return fd;
}

int MDnsUtilImpl::Send(int fd, int port, const uint8_t* buff, int len) 
{
    int serverlen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    
    bzero((char *) &addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_BROADCAST;
    addr.sin_port = htons(port);
    
    return sendto(fd, buff, len, 0, (sockaddr*)&addr, serverlen);
}

int MDnsUtilImpl::Recv(int fd, uint8_t* buff, int len, struct sockaddr_in* peer) 
{
    int serverlen = sizeof(struct sockaddr_in);
    bzero((char *) peer, sizeof(struct sockaddr_in));
    
    return recvfrom(fd, buff, len, 0, (sockaddr*)peer, (socklen_t*)&serverlen);
}

std::vector<mdns_service_t>& MDnsUtilImpl::GetServices()
{
    return mServices;
}

MDnsUtil::MDnsUtil()
{
    mImpl = new MDnsUtilImpl();
}

MDnsUtil::~MDnsUtil()
{
    delete mImpl;
}

bool MDnsUtil::Resolve(std::string service, int scanTime)
{
    return mImpl->Resolve(service, scanTime);
}

std::vector<mdns_service_t>& MDnsUtil::GetServices()
{
    return mImpl->GetServices();
}