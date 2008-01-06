//
//  PCapPacket.m
//  CapKit
//
//  Created by Lachlan O'Dea on 17/12/07.
//

#import "PCapPacket.h"


@implementation PCapPacket

- (id)initWithPacket:(const struct pcap_pkthdr* const)header
                data:(const u_char* const)data {
    self = [super init];
    if (self != nil) {
        double const seconds = header->ts.tv_sec
        + (header->ts.tv_usec/1000.0/1000.0);
        captureTime = [[NSDate dateWithTimeIntervalSince1970:seconds] retain];
        captureLength = header->caplen;
        length = header->len;
        packet = [[NSData alloc] initWithBytes:data length:captureLength];
    }
    return self;
}

- (void) dealloc {
    [packet release];
    [captureTime release];
    
    [super dealloc];
}

@synthesize captureTime;
@synthesize captureLength;
@synthesize length;
@synthesize packet;

@end
