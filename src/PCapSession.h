//
//  PCapSession.h
//  CapKit
//
//  Created by Lachlan O'Dea on 17/12/07.
//

#import <Foundation/Foundation.h>

#include <pcap.h>

#import "PCapStats.h"


enum DispatchResponse_ {
    SUCCESS,
    INTERRUPTED,
    ERROR
} typedef DispatchResponse;

@interface PCapSession : NSObject
{
@private
    pcap_t* pcap;
    FILE* cFilePointer;
    NSNotificationCenter* notificationCenter;
    NSString* currentFilter;
}

+ (PCapSession*)openWithDevice:(NSString*)device
                       snaplen:(int)snaplen
                   promiscuous:(BOOL)promiscuous
                         error:(NSError**)outError;

+ (PCapSession*)openWithFileDescriptor:(int)descriptor
                                 error:(NSError**)outError;

- (id)initWithPCap:(pcap_t*)initPcap filePointer:(FILE*)filePointer;

@property(readonly) int snapshotLength;

- (PCapStats*)statistics:(NSError**)outError;

- (BOOL)installFilter:(NSString*)filter optimize:(BOOL)optimize
              netmask:(bpf_u_int32)netmask error:(NSError**)outError;

@property(readonly) int datalink;

- (BOOL)setDataLink:(int)newDataLink error:(NSError**)outError;

@property(retain) NSNotificationCenter* notificationCenter;

- (BOOL)blocking:(BOOL*)outBool error:(NSError**)outError;

- (BOOL)setBlocking:(BOOL)blocking error:(NSError**)outError;

- (DispatchResponse)dispatchWithMax:(int)max 
                        eventSource:(id)eventSource 
                              error:(NSError**)outError;

- (void)interrupt;

- (void)close;

+ (NSString*)version;

@end
