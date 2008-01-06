//
//  PacketDumpDoc.m
//  CapKit
//
//  Created by Lachlan O'Dea on 29/12/07.
//

#import "PacketDumpDoc.h"
#import "CapKit.h"


@implementation PacketDumpDoc

- (id)init {
    self = [super init];
    if (self != nil) {
        packets = [[NSMutableArray alloc] initWithCapacity:1000];
    }
    return self;
}

- (void)dealloc {
    [packets release];
    [super dealloc];
}

- (NSString *)windowNibName {
    // Implement this to return a nib to load OR implement -makeWindowControllers to manually create your controllers.
    return @"DocumentWindow";
}

- (NSData *)dataOfType:(NSString *)typeName error:(NSError **)outError
{
    // Insert code here to write your document to data of the specified type. If the given outError != NULL, ensure that you set *outError when returning nil.

    // You can also choose to override -fileWrapperOfType:error:, -writeToURL:ofType:error:, or -writeToURL:ofType:forSaveOperation:originalContentsURL:error: instead.

    // For applications targeted for Panther or earlier systems, you should use the deprecated API -dataRepresentationOfType:. In this case you can also choose to override -fileWrapperRepresentationOfType: or -writeToFile:ofType: instead.

    NSAssert(NO, @"Saving not supported");
    return nil;
}

- (BOOL)readFromURL:(NSURL*)absoluteURL 
             ofType:(NSString*)typeName
              error:(NSError**)outError {
    NSAssert([typeName isEqualToString:@"tcpdump"], @"Unknown type name");
    
    if (![absoluteURL isFileURL]) {
        if (outError != NULL) {
            *outError = [NSError errorWithDomain:SIMPLECAP_ERRORDOMAIN
                                            code:SIMPLECAPERR_UNSUPPORTED
                                        userInfo:[NSDictionary dictionaryWithObject:@"Non-file URLs are not supported"
                                                                             forKey:SIMPLECAPKEY_MESSAGE]];
        }
        return NO;
    }
    
    NSFileHandle* fileHandle = [NSFileHandle fileHandleForReadingAtPath:
                                [absoluteURL path]];
    NSAssert(fileHandle != nil, @"File not found");
    
    PCapSession* session = [PCapSession openWithFileDescriptor: [fileHandle fileDescriptor]
                                                         error:outError];
    if (session == nil) {
        return NO;
    }
    [[NSNotificationCenter defaultCenter] addObserver:self 
                                             selector:@selector(packetRead:) 
                                                 name:PCAP_NOTIFY_PACKET
                                               object:self];
    const DispatchResponse response = [session dispatchWithMax:-1
                                                   eventSource:self 
                                                         error:outError];
    [session close];
    [[NSNotificationCenter defaultCenter] removeObserver:self 
                                                    name:PCAP_NOTIFY_PACKET 
                                                  object:self];
    return response == SUCCESS;
}

- (void)packetRead:(NSNotification*)notification {
    NSDictionary* info = [notification userInfo];
    PCapPacket* packet = [info objectForKey:PCAPKEY_PACKET];
    [packets addObject:packet];
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)view {
    return [packets count];
}

- (id)tableView:(NSTableView*)view 
objectValueForTableColumn:(NSTableColumn*)column
            row:(NSInteger)rowIndex {
    NSString* columnId = [column identifier];
    PCapPacket* packet = [packets objectAtIndex:rowIndex];
    if ([columnId isEqualToString:@"timestamp"]) {
        return packet.captureTime;
    }
    if ([columnId isEqualToString:@"length"]) {
        return [NSNumber numberWithInt:packet.length];
    }
    if ([columnId isEqualToString:@"frameType"]) {
        const char* data = (const char*)[packet.packet bytes];
        unsigned short etherType = NSSwapBigShortToHost(*(unsigned short*)(data + 12));
        switch (etherType) {
            case 0x0800: return @"IPv4";
            case 0x0806: return @"ARP";
            default: return [NSNumber numberWithUnsignedShort:etherType];
        }
    }
    if ([columnId isEqualToString:@"ipType"]) {
        const unsigned char* data = (const unsigned char*)[packet.packet bytes];
        unsigned short etherType = NSSwapBigShortToHost(*(unsigned short*)(data + 12));
        if (etherType == 0x0800) {
            unsigned char protocol = data[14 + 9];
            switch (protocol) {
                case 1: return @"ICMP";
                case 6: return @"TCP";
                case 17: return @"UDP";
                default: return [NSNumber numberWithUnsignedShort:protocol];
            }
        }
        return @"";
    }
    return @"Unknown";
}

@end
