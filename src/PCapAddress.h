//
//  PCapAddress.h
//  CapKit
//
//  Created by Lachlan O'Dea on 17/12/07.
//

#import <Foundation/Foundation.h>

#include <pcap.h>


@interface PCapAddress : NSObject {

@private
    
    pcap_addr_t* pcapAddress;


}

- (id)initWithAddress:(pcap_addr_t*)initAddress;

@property(readonly) BOOL inet;
@property(readonly) BOOL inet6;
@property(readonly) int addressFamily;
@property(readonly) NSData* address;
@property(readonly) NSData* netmask;
@property(readonly) NSData* broadcast;
@property(readonly) NSData* destinationAddress;

@end
