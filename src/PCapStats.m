//
//  PCapStats.m
//  CapKit
//
//  Created by Lachlan O'Dea on 17/12/07.
//

#import "PCapStats.h"


@implementation PCapStats

- (id)initWithStats:(const struct pcap_stat* const)pcapStats {
    self = [super init];
    if (self != nil) {
        received = pcapStats->ps_recv;
        dropped = pcapStats->ps_drop;
    }
    return self;
}

@synthesize received;
@synthesize dropped;

@end
