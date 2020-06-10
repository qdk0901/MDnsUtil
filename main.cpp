#include <stdio.h>
#include <vector>

#include "MDnsUtil.h"

int main()
{
    MDnsUtil util;
    
    if(!util.Resolve("_airplay._tcp.local", 1))
        return -1;
    
    std::vector<mdns_service_t> services = util.GetServices();
    
    for (int i = 0; i < services.size(); i++) {
        printf("%s @ %s:%d\n", services[i].name.c_str(), services[i].host.c_str(), services[i].port);
    }
    
    return 0;
}
