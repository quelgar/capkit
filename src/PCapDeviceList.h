//
//  PCapDeviceList.h
//  CapKit
//
//  Created by Lachlan O'Dea on 22/12/07.
//

#import <Foundation/Foundation.h>

#include <pcap.h>


@interface PCapDeviceList : NSObject {

    @private
    
    pcap_if_t* pcapInterfaceHead;
    
}

+ (NSString*)lookupDevice: (NSError**)outError;

- (id)init: (NSError**)outError;

- (void)close;

// returns an array of PCapDevice objects
@property(readonly) NSArray* devices;

@end
