//
//  STMDefaultContentProtocol.m
//  ios-sdk
//
//  Created by xpwu on 2016/11/24.
//  Copyright © 2016年 xpwu.xpwu. All rights reserved.
//

#import "STMDefaultContentProtocol.h"

/*
 * content protocol:
 *    request ---
 *      reqid | headers | header-end-flag | data
 *        reqid: 4 bytes, net order;
 *        headers: < key-len | key | value-len | value > ... ;  [optional]
 *          key-len: 1 byte,  key-len = sizeof(key);
 *          value-len: 1 byte, value-len = sizeof(value);
 *        header-end-flag: 1 byte, === 0;                       [optional]
 *        data:       [optional]
 *
 *    response ---
 *      reqid | status | data
 *        reqid: 4 bytes, net order;
 *        status: 1 byte, 0---success, 1---failed
 *        data: if status==success, data=<app data>    [optional]
 *              if status==failed, data=<error reason>
 *
 */

@implementation STMDefaultContentProtocol

#pragma mark - ContentProtocol

-(void)onopen:(void (^)(void))callback {
  if (callback != nil) {
    callback();
  }
}

-(void)onclose {}

-(STMResponse*)parse:(NSData*)message {
  const uint8_t* p = (const uint8_t*)message.bytes;
  
  STMResponse* res = [STMResponse defaultResponse];
  res.reqID = ntohl(*(const uint32_t*)p);
  p += 4;
  
  res.status = (STMResponseStatus)*p;
  p += 1;
  
  if (message.length == 5) {
    return res;
  }
  
  res.data = [message subdataWithRange:NSMakeRange(6, message.length-6)];
  
  return res;
}

-(NSData*)build:(NSData*)body
    withHeaders:(NSDictionary<NSString*, NSString*>*)headers
      withReqID:(uint32_t)reqID {
  NSInteger length = 0;
  NSInteger* lengthp = &length;
  BOOL __block failed = NO;
  [headers enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, NSString * _Nonnull obj, BOOL * _Nonnull stop) {
    if (key.length > 255 || obj.length > 255) {
      *stop = YES;
      failed = YES;
    }
    *lengthp += key.length + obj.length + 1 + 1;
  }];
  
  if (failed == YES) {
    return nil;
  }
  
  length += 4 + 1 + ((body == nil)? 0: body.length);
  
  char* buffer = calloc(length, sizeof(char));
  char* __block p = buffer;
  *(uint32_t*)p = htonl(reqID);
  p += 4;
  
  [headers enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key
                                               , NSString * _Nonnull obj
                                               , BOOL * _Nonnull stop) {
    *p = (char)key.length;
    p += 1;
    if (NO == [key getCString:p maxLength:(length-(p-buffer)) encoding:NSASCIIStringEncoding]) {
      failed = YES;
      *stop = YES;
      return;
    }
    p += key.length;
    
    *p = (char)obj.length;
    p += 1;
    if (NO == [obj getCString:p maxLength:(length-(p-buffer)) encoding:NSASCIIStringEncoding]) {
      failed = YES;
      *stop = YES;
      return;
    }
    p += obj.length;
  }];
  
  if (failed == YES) {
    return nil;
  }
  
  *p = 0;
  p += 1;
  
  if (body != nil) {
    [body getBytes:p];
  }
  
  return [NSData dataWithBytesNoCopy:buffer length:length];
}

-(NSData*)buildFailedMessage:(NSString*)error withReqid:(uint32_t)reqID {
  NSData* err = [error dataUsingEncoding:NSUTF8StringEncoding];
  char* buffer = calloc(err.length + 4 + 1, sizeof(char));
  [err getBytes:buffer+5];
  buffer[4] = 1;
  *(uint32_t*)buffer = htonl(reqID);
  
  return [NSData dataWithBytesNoCopy:buffer length:err.length + 4 + 1];
}
@end







