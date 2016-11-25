//
//  STMResponse.h
//  ios-sdk
//
//  Created by xpwu on 2016/11/24.
//  Copyright © 2016年 xpwu.xpwu. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum {
  STMResponseStatusSuccess = 0,
  STMResponseStatusFailed = 1
} STMResponseStatus;

@interface STMResponse : NSObject
@property(nonatomic) uint32_t reqID;
@property(nonatomic) STMResponseStatus status;
@property(nonatomic) NSData* data;

+(instancetype)defaultResponse;
@end
