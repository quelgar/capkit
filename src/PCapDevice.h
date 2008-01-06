//
//  PCapDevice.h
//  CapKit
//
//  Created by Lachlan O'Dea on 22/12/07.
//

#import <Foundation/Foundation.h>

#include <pcap.h>


@interface PCapDevice : NSObject {

    @private
    pcap_if_t* pcapInterface;
    
}

+ (BOOL)lookupNetwork: (NSString*)device
              network:(bpf_u_int32*)network
                 mask:(bpf_u_int32*)mask
                error: (NSError**)outError;

- (id)initWithInterface:(pcap_if_t*)initInterface;

@property(readonly) NSString* name;
@property(readonly) NSString* description;
@property(readonly) NSArray* addresses;
@property(readonly) BOOL loopback;

@end
