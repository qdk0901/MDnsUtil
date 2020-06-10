#ifndef _MDNS_UTIL_H_
#define _MDNS_UTIL_H_
#include <string>
#include <vector>

typedef struct mdns_service_s {
    std::string host;
    std::string name;
    int port;
} mdns_service_t;

class MDnsUtilImpl;
class MDnsUtil
{
public:
    MDnsUtil();
    ~MDnsUtil();
    
    bool Resolve(std::string service, int scanTime);
    std::vector<mdns_service_t>& GetServices();
    
private:
    MDnsUtilImpl* mImpl;
};

#endif