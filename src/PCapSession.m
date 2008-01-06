//
//  PCapAddress.m
//  CapKit
//
//  Created by Lachlan O'Dea on 17/12/07.
//

#import "PCapSession.h"
#import "PCapPacket.h"
#import "Util.h"
#import "Globals.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


struct HandlerUserData_ {
    id eventSource;
    PCapSession* session;
} typedef HandlerUserData;

static void pcapHandler(u_char* const user, const struct pcap_pkthdr* const header,
                        const u_char* const packetData) {
    HandlerUserData* userData = (HandlerUserData*)user;
    PCapSession* const session = userData->session;
    PCapPacket* const packet = [[PCapPacket alloc] initWithPacket:header
                                                             data:packetData];
    [session.notificationCenter postNotificationName:PCAP_NOTIFY_PACKET
     object:userData->eventSource
     userInfo:[NSDictionary dictionaryWithObject:packet forKey:PCAPKEY_PACKET]];
    [packet release];
}


@implementation PCapSession

+ (PCapSession*)openWithDevice:(NSString*)device
                       snaplen:(int)snaplen
                   promiscuous:(BOOL)promiscuous 
                         error:(NSError**)outError {
    NSAssert(device == nil, @"PCapDevice cannot be nil");
    char errorBuffer[PCAP_ERRBUF_SIZE];
    errorBuffer[0] = 0;
    pcap_t* pcap = pcap_open_live([device cStringUsingEncoding:NSASCIIStringEncoding],
                                  snaplen, promiscuous, 0, errorBuffer);
    if (pcap == NULL) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_OPENDEVICE, errorBuffer);
        }
        return nil;
    }
    return [[[PCapSession alloc] initWithPCap:pcap filePointer:NULL] autorelease];
}

+ (PCapSession*)openWithFileDescriptor:(int)descriptor
                                 error:(NSError**)outError {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    errorBuffer[0] = 0;
    FILE* fp = fdopen(descriptor, "r");
    if (fp == NULL) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_OPENFILE, strerror(errno));
        }
        return nil;
    }
    pcap_t* pcap = pcap_fopen_offline(fp, errorBuffer);
    if (pcap == NULL) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_OPENFILE, errorBuffer);
        }
        return nil;
    }
    return [[[PCapSession alloc] initWithPCap:pcap filePointer:fp] autorelease];
}

- (id)initWithPCap:(pcap_t*)initPcap filePointer:(FILE*)filePointer {
    self = [super init];
    if (self == nil) {
        pcap_close(pcap);
        fclose(filePointer);
    }
    else {
        pcap = initPcap;
        cFilePointer = filePointer;
        notificationCenter = [[NSNotificationCenter defaultCenter] retain];
    }
    return self;
}

- (void)close {
    if (pcap != NULL) {
        pcap_close(pcap);
        pcap = NULL;
    }
    if (cFilePointer != NULL) {
        fclose(cFilePointer);
        cFilePointer = NULL;
    }
}

- (void)dealloc {
    [notificationCenter release];
    [self close];
    [super dealloc];
}

- (void)finalize {
    [self close];
    [super finalize];
}

@dynamic snapshotLength;
- (int)snapshotLength {
    return pcap_snapshot(pcap);
}

- (PCapStats*)statistics:(NSError**)outError {
    struct pcap_stat stats;
    if (pcap_stats(pcap, &stats) < 0) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_STATS, pcap_geterr(pcap));
        }
        return nil;
    }
    return [[[PCapStats alloc] initWithStats:&stats] autorelease];
}

- (BOOL)installFilter:(NSString*)filter
             optimize:(BOOL)optimize
              netmask:(bpf_u_int32)netmask 
                error:(NSError**)outError {
    struct bpf_program newProg;
    // pcap_compile declares the filter string as non-const, so maybe it might change it? Don't know.
    // Anyway, play it safe an make a copy to pass to pcap_compile
    char* const filterBuf = malloc([filter length] + 1);
    const BOOL copyResult = [filter getCString:filterBuf
                                     maxLength:[filter length] + 1
                                      encoding:NSASCIIStringEncoding];
    NSAssert(copyResult, @"Copying filter string to buffer failed");
    if (pcap_compile(pcap, &newProg,
                     filterBuf,
                     optimize ? 1 : 0, netmask) < 0) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_COMPILEFILTER, pcap_geterr(pcap));
        }
        free(filterBuf);
        return NO;
    }
    free(filterBuf);
    if (pcap_setfilter(pcap, &newProg) < 0) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_SETFILTER, pcap_geterr(pcap));
        }
        pcap_freecode(&newProg);
        return NO;
    }
    pcap_freecode(&newProg);
    if (currentFilter != nil) {
        [currentFilter release];
    }
    currentFilter = filter;
    [currentFilter retain];
    return YES;
}

@dynamic datalink;
- (int)datalink {
    return pcap_datalink(pcap);
}

- (BOOL)setDataLink: (int)newDataLink error:(NSError**)outError {
    if (pcap_set_datalink(pcap, newDataLink) < 0) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_SETDATALINK, pcap_geterr(pcap));
        }
        return NO;
    }
    return YES;
}

@synthesize notificationCenter;

- (BOOL)blocking:(BOOL*)outBool error:(NSError**)outError {
    NSAssert(outBool != NULL, @"output boolean cannout be NULL");
    char errorBuf[PCAP_ERRBUF_SIZE];
    errorBuf[0] = 0;
    int nonBlock = pcap_getnonblock(pcap, errorBuf);
    if (nonBlock < 0) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_GETBLOCKING, errorBuf);
        }
        return NO;
    }
    return !nonBlock;
}

- (BOOL)setBlocking:(BOOL)blocking error:(NSError**)outError {
    char errorBuf[PCAP_ERRBUF_SIZE];
    errorBuf[0] = 0;
    if (pcap_setnonblock(pcap, !blocking, errorBuf) < 0) {
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_SETBLOCKING, errorBuf);
        }
        return NO;
    }
    return YES;
}

- (DispatchResponse)dispatchWithMax:(int)max 
                        eventSource:(id)eventSource 
                              error:(NSError**)outError {
    HandlerUserData userData;
    userData.session = self;
    userData.eventSource = eventSource;
    const int result = pcap_dispatch(pcap, max, &pcapHandler, (u_char*)&userData);
    if (result == -2) {
        // pcap_breakloop called
        return INTERRUPTED;
    }
    if (result == -1) {
        // error
        if (outError != NULL) {
            *outError = nsErrorFromPCapError(PCAPERR_DISPATCH, pcap_geterr(pcap));
        }
        return ERROR;
    }
    return SUCCESS;
}

- (void)interrupt {
    pcap_breakloop(pcap);
}

+ (NSString*)version {
    return [NSString stringWithCString:pcap_lib_version() encoding:NSASCIIStringEncoding];
}

@end
