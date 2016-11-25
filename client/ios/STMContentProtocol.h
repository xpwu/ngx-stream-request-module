//
//  STMContentProtocol.h
//  ios-sdk
//
//  Created by xpwu on 2016/11/24.
//  Copyright © 2016年 xpwu.xpwu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "STMResponse.h"

@protocol STMContentProtocol <NSObject>

-(void)onopen:(void (^)(void))callback;
-(void)onclose;
-(STMResponse*)parse:(NSData*)message;
-(NSData*)build:(NSData*)body
    withHeaders:(NSDictionary<NSString*, NSString*>*)headers
      withReqID:(uint32_t)reqID;

-(NSData*)buildFailedMessage:(NSString*)error withReqid:(uint32_t)reqID;

@end
