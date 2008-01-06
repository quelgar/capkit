//
//  Util.m
//  CapKit
//
//  Created by Lachlan O'Dea on 22/12/07.
//

#import "Util.h"
#import "Globals.h"

NSError* nsErrorFromPCapError(NSInteger const code, const char* const errorBuf) {
    NSString* const errorMsg = [NSString stringWithCString:errorBuf
                                                  encoding:NSASCIIStringEncoding];
    NSDictionary* const errorDict = [NSDictionary
                                     dictionaryWithObject:errorMsg
                                     forKey:PCAPKEY_ERROR];
    return [NSError errorWithDomain:PCAP_ERRORDOMAIN
                               code:PCAPERR_FINDDEV
                           userInfo:errorDict];    
}
