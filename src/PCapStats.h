//
//  PCapStats.h
//  CapKit
//
//  Created by Lachlan O'Dea on 17/12/07.
//

#import <Foundation/Foundation.h>

#include <pcap.h>


@interface PCapStats : NSObject {
@private
    int received;
    int dropped;
}

- (id)initWithStats:(const struct pcap_stat* const)pcapStats;

@property(readonly) int received;

@property(readonly) int dropped;

@end
