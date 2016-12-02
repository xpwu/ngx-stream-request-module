//
//  STMResponse.m
//  ios-sdk
//
//  Created by xpwu on 2016/11/24.
//  Copyright © 2016年 xpwu.xpwu. All rights reserved.
//

#import "STMResponse.h"

#import "Log.h"

@implementation STMResponse
+(instancetype)defaultResponse {
  STMResponse* res = [[STMResponse alloc]init];
  res.reqID = 0;
  res.status = STMResponseStatusSuccess;
  res.data = nil;
  return res;
}
@end
