//
//  PCapPacket.h
//  CapKit
//
//  Created by Lachlan O'Dea on 17/12/07.
//

#import <Foundation/Foundation.h>

#include <pcap.h>


@interface PCapPacket : NSObject {
@private
    NSDate* captureTime;
    int captureLength;
    int length;
    NSData* packet;
}

- (id)initWithPacket:(const struct pcap_pkthdr* const)header
                data:(const u_char* const)data;

@property(readonly) NSDate* captureTime;

@property(readonly) int captureLength;

@property(readonly) int length;

@property(readonly) NSData* packet;

@end
