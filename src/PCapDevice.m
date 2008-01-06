//
//  PCapDevice.m
//  CapKit
//
//  Created by Lachlan O'Dea on 22/12/07.
//

#import "PCapDevice.h"
#import "Util.h"
#import "Globals.h"
#import "PCapAddress.h"


@implementation PCapDevice

+ (BOOL)lookupNetwork:(NSString*)device network:(bpf_u_int32*)network
                 mask:(bpf_u_int32*)mask error:(NSError**)outError {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    errorBuffer[0] = 0;
    if (pcap_lookupnet([device cStringUsingEncoding:NSASCIIStringEncoding],
                       network, mask, errorBuffer) < 0) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_LOOKUPNET, errorBuffer);
        }
        return NO;
    }
    return YES;
}


- (id)initWithInterface: (pcap_if_t*)initInterface {
    self = [super init];
    if (self != nil) {
        pcapInterface = initInterface;
    }
    return self;
}

@dynamic name;
- (NSString*)name {
    return [NSString stringWithCString:pcapInterface->name encoding:NSASCIIStringEncoding];
}

@dynamic description;
- (NSString*)description {
    if (pcapInterface->description == NULL) {
        return @"No description";
    }
    return [NSString stringWithCString:pcapInterface->description encoding:NSASCIIStringEncoding];
}

@dynamic addresses;
- (NSArray*)addresses {
    NSMutableArray* const addresses = [NSMutableArray arrayWithCapacity:4];
    pcap_addr_t* addressPtr = pcapInterface->addresses;
    while (addressPtr != NULL) {
        id const pcapAddress = [[PCapAddress alloc] initWithAddress:addressPtr];
        [addresses addObject:pcapAddress];
        [pcapAddress release];
        addressPtr = addressPtr->next;
    }
    return addresses;
}

@dynamic loopback;
- (BOOL)loopback {
    return (pcapInterface->flags & PCAP_IF_LOOPBACK) != 0;
}


@end
