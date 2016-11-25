//
//  STMNet.h
//  ios-sdk
//
//  Created by xpwu on 2016/11/23.
//  Copyright © 2016年 xpwu.xpwu. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum{
  STMNetStatusConnecting, 
  STMNetStatusOpen,
  STMNetStatusClosed
  
} STMNetStatus;

@interface STMNet : NSObject <NSStreamDelegate>

@property(nonatomic) void (^onopen)();
@property(nonatomic) void (^onclose)(NSString*);
@property(nonatomic) void (^onmessage)(NSData*);
@property(nonatomic,readonly) STMNetStatus status;

// unit: s
@property(nonatomic) NSTimeInterval hearbeatTime;
@property(nonatomic) NSTimeInterval transmissionTimeout;
@property(nonatomic) NSTimeInterval openTimeout;

-(instancetype)initWithHost:(NSString*)host andPort:(UInt16)port;

-(void)open;
-(void)close;
-(void)send:(NSData*)data;

@end
