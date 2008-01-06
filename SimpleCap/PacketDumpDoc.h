//
//  PacketDumpDoc.h
//  CapKit
//
//  Created by Lachlan O'Dea on 29/12/07.
//

#import <Cocoa/Cocoa.h>

#define SIMPLECAP_ERRORDOMAIN @"net.sf.CapKit.SimpleCap.ErrorDomain"

#define SIMPLECAPKEY_MESSAGE @"SimpleCap.Message"

#define SIMPLECAPERR_UNSUPPORTED 1666


@interface PacketDumpDoc : NSDocument {

    @private
    NSMutableArray* packets;
    
}

- (void)packetRead:(NSNotification*)notification;

- (NSInteger)numberOfRowsInTableView:(NSTableView*)view;

- (id)tableView:(NSTableView*)view 
objectValueForTableColumn:(NSTableColumn*)column
            row:(NSInteger)rowIndex;    

@end
