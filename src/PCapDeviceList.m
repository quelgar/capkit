//
//  PCapDeviceList.m
//  CapKit
//
//  Created by Lachlan O'Dea on 22/12/07.
//

#import "PCapDeviceList.h"
#import "Util.h"
#import "Globals.h"
#import "PCapDevice.h"


@implementation PCapDeviceList

+ (NSString*)lookupDevice: (NSError**)outError {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    errorBuffer[0] = 0;
    const char* const devName = pcap_lookupdev(errorBuffer);
    if (devName == NULL) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_LOOKUPDEV, errorBuffer);
        }
        return nil;
    }
    return [NSString stringWithCString:devName encoding:NSASCIIStringEncoding];
}


- (id)init: (NSError**)outError {
    self = [super init];
    if (self == nil) return nil;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    errorBuffer[0] = 0;
    if (pcap_findalldevs(&pcapInterfaceHead, errorBuffer) < 0) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_FINDDEV, errorBuffer);
        }
        [self release];
        return nil;
    }
    return self;
}

@dynamic devices;
- (NSArray*)devices {
    NSMutableArray* const devList = [NSMutableArray arrayWithCapacity:4];
    for (pcap_if_t* ifPtr = pcapInterfaceHead; ifPtr != NULL;
         ifPtr = ifPtr->next) {
        PCapDevice* device = [[PCapDevice alloc] initWithInterface:ifPtr];
        [devList addObject:device];
        [device release];
    }
    return devList;
}

- (void)close {
    if (pcapInterfaceHead != NULL) {
        pcap_freealldevs(pcapInterfaceHead);
        pcapInterfaceHead = NULL;
    }
}

- (void)dealloc {
    [self close];
    [super dealloc];
}

- (void)finalize {
    [self close];
    [super finalize];
}

@end
