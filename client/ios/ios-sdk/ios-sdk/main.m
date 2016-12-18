//
//  main.m
//  ios-sdk
//
//  Created by xpwu on 2016/11/23.
//  Copyright © 2016年 xpwuxpwu. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "STMClient.h"

@interface RunLoopSource : NSObject
-(void)perform:(id)message;
@end

@implementation RunLoopSource
-(void)perform:(id)message {
  void (^msg)(void) = message;
  msg();
}
@end

#define RUNLOOP_INIT \
  RunLoopSource* src = [[RunLoopSource alloc]init]; \
  [[NSRunLoop mainRunLoop]performSelector:@selector(perform:) \
                                 target:src argument:^(void) {


#define RUNLOOP_RUN \
  } \
  order:0 modes:@[NSDefaultRunLoopMode]]; \
      \
  [[NSRunLoop mainRunLoop]run];


int main(int argc, const char * argv[]) {
  @autoreleasepool {
    
    RUNLOOP_INIT
    
      STMClient* client = [[STMClient alloc]init];
    
    STMClient* __weak client_ = client;
      [client setConnectHost:@"ssl://www.xpwu.me" port:10005
                   onSuccess:^{
                      NSLog(@"connect successful");
                    }
                    onFailed:^(NSString * error) {
                      NSLog(@"%@", error);
                      [client_ addRequestBody:[@"add message" dataUsingEncoding:NSUTF8StringEncoding]
                                     headers:@{@"h":@"test", @"ua": @"request ua"}
                                   onSuccess:^(NSData * data) {
                                     NSLog(@"%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
                                   }
                                    onFailed:^(NSString * error) {
                                      NSLog(@"%@", error);
                                    }
                                  onComplete:^{
                                    NSLog(@"request <message headers> complete");
                                  }];
                    }];
    
      client.onpush = ^(NSData* data) {
              NSLog(@"[push]---%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
            };
            
      [client setBlockRequestOnConnected:[@"block message" dataUsingEncoding:NSUTF8StringEncoding]
                                 headers:@{@"name": @"block message"}
                               onSuccess:^BOOL(NSData * data) {
                                       NSLog(@"%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
                                       return YES;
                                     }
                                onFailed:^(NSString * error) {
                                        NSLog(@"%@", error);
                                      }
                              onComplete:^{
                                      NSLog(@"block message complete");
                                    }];
    
      [client addRequestBody:[@"add message" dataUsingEncoding:NSUTF8StringEncoding]
                     headers:@{@"h":@"test", @"ua": @"request ua"}
                   onSuccess:^(NSData * data) {
                           NSLog(@"%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
                         }
                    onFailed:^(NSString * error) {
                            NSLog(@"%@", error);
                          }
                  onComplete:^{
                          NSLog(@"request <message headers> complete");
                        }];
    
    [client addRequestBody:nil
                   headers:@{@"h":@"test", @"ua": @"request ua 2"}
                 onSuccess:^(NSData * data) {
                   NSLog(@"%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
                 }
                  onFailed:^(NSString * error) {
                    NSLog(@"%@", error);
                  }
                onComplete:^{
                  NSLog(@"request <nil headers> complete");
                }];
    
    [client addRequestBody:nil
                   headers:nil
                 onSuccess:^(NSData * data) {
                   NSLog(@"%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
                 }
                  onFailed:^(NSString * error) {
                    NSLog(@"%@", error);
                  }
                onComplete:^{
                  NSLog(@"request <nil nil> complete");
                }];
    
    [client addRequestBody:nil
                   headers:@{@"h":@"test", @"ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);ua NSLog(, [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);": @"request ua 2"}
                 onSuccess:^(NSData * data) {
                   NSLog(@"%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
                 }
                  onFailed:^(NSString * error) {
                    NSLog(@"%@", error);
                  }
                onComplete:^{
                  NSLog(@"request <nil 'long header'> complete");
                }];
    
    RUNLOOP_RUN
    
  }
    return 0;
}
