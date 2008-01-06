//
//  PCapAddress.m
//  CapKit
//
//  Created by Lachlan O'Dea on 17/12/07.
//

#import "PCapAddress.h"
#include <sys/socket.h>
#include <netinet/in.h>

static NSData* extractAddress(const struct sockaddr* const sockAddr) {
    if (sockAddr->sa_family == AF_INET) {
        const struct sockaddr_in* inAddr = (const struct sockaddr_in*)sockAddr;
        return [NSData dataWithBytes:&(inAddr->sin_addr)
                              length:sizeof(inAddr->sin_addr)];
    }
    else if (sockAddr->sa_family == AF_INET6) {
        const struct sockaddr_in6* in6Addr = (const struct sockaddr_in6*)sockAddr;
        return [NSData dataWithBytes:&(in6Addr->sin6_addr)
                              length:sizeof(in6Addr->sin6_addr)];
    }
    return [NSData dataWithBytes:&(sockAddr->sa_data)
                          length:(sockAddr->sa_len
                                  - sizeof(sockAddr->sa_len)
                                  - sizeof(sockAddr->sa_family))];
}


@implementation PCapAddress

- (id)initWithAddress:(pcap_addr_t*)initAddress {
    self = [super init];
    if (self != nil) {
        pcapAddress = initAddress;
    }
    return self;
}

@dynamic inet;
- (BOOL)inet {
    return pcapAddress->addr->sa_family == AF_INET;
}

@dynamic inet6;
- (BOOL)inet6 {
    return pcapAddress->addr->sa_family == AF_INET6;
}

@dynamic addressFamily;
- (int)addressFamily {
    return pcapAddress->addr->sa_family;
}

@dynamic address;
- (NSData*)address {
    return extractAddress(pcapAddress->addr);
}

@dynamic netmask;
- (NSData*)netmask {
    return extractAddress(pcapAddress->netmask);
}

@dynamic broadcast;
- (NSData*)broadcast {
    return extractAddress(pcapAddress->broadaddr);
}

@dynamic destinationAddress;
- (NSData*)destinationAddress {
    return extractAddress(pcapAddress->dstaddr);
}

@end
