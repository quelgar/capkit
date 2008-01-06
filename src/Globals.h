/*
 *  Globals.h
 *  CapKit
 *
 *  Created by Lachlan O'Dea on 23/12/07.
 *
 */

#define PCAP_ERRORDOMAIN @"net.sf.CapKit.ErrorDomain"

#define PCAPKEY_ERROR @"PCapErrorMessage"
#define PCAPKEY_PACKET @"PCapPacket"

#define PCAPERR_FINDDEV 666
#define PCAPERR_LOOKUPDEV 667
#define PCAPERR_LOOKUPNET 668
#define PCAPERR_COMPILEFILTER 669
#define PCAPERR_OPENDEVICE 670
#define PCAPERR_OPENFILE 671
#define PCAPERR_STATS 672
#define PCAPERR_SETFILTER 673
#define PCAPERR_SETDATALINK 674
#define PCAPERR_GETBLOCKING 675
#define PCAPERR_SETBLOCKING 676
#define PCAPERR_DISPATCH 677

#define PCAP_NOTIFY_PACKET @"net.sf.CapKit.NewPacket"