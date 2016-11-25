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
//    STMNet* net = [[STMNet alloc]initWithHost:@"127.0.0.1" andPort:10003];
//    
//    [[NSRunLoop mainRunLoop]performSelector:@selector(open)
//                                     target:net
//                                   argument:nil
//                                      order:0
//                                      modes:@[NSDefaultRunLoopMode]];
    
//    RunLoopSource* src = [[RunLoopSource alloc]init];
//    [[NSRunLoop mainRunLoop]performSelector:@selector(perform:)
//                                     target:src argument:^(void)
//    {
//                                     
//                                     
//    }
//                                      order:0 modes:@[NSDefaultRunLoopMode]];
//    
//    [[NSRunLoop mainRunLoop]run];
    
    RUNLOOP_INIT
    
      STMClient* client = [[STMClient alloc]init];
            
      [client setConnectHost:@"127.0.0.1" port:10003
                   onSuccess:^{
                      NSLog(@"connect successful");
                    }
                    onFailed:^(NSString * error) {
                      NSLog(@"%@", error);
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
            
      [client addRequestBody:[@"xadd message" dataUsingEncoding:NSUTF8StringEncoding]
                     headers:@{@"h":@"test", @"ua": @"request ua"}
                   onSuccess:^(NSData * data) {
                           NSLog(@"%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
                         }
                    onFailed:^(NSString * error) {
                            NSLog(@"%@", error);
                          }
                  onComplete:^{
                          NSLog(@"add message complete");
                        }];
    
    RUNLOOP_RUN
    
//    STMClient* client = [[STMClient alloc]init];
//    
//    [client setConnectHost:@"127.0.0.1" port:10003 onSuccess:^{
//      NSLog(@"connect successful");
//    } onFailed:^(NSString * error) {
//      NSLog(@"%@", error);
//    }];
//    
//    client.onpush = ^(NSData* data) {
//      NSLog(@"[push]---%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
//    };
//    
//    [client setBlockRequestOnConnected:[@"block message" dataUsingEncoding:NSUTF8StringEncoding]
//                               headers:@{@"name": @"block message"}
//                             onSuccess:^BOOL(NSData * data) {
//      NSLog(@"%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
//      return YES;
//    }
//                              onFailed:^(NSString * error) {
//      NSLog(@"%@", error);
//    }
//                            onComplete:^{
//      NSLog(@"block message complete");
//    }];
//    
//    [client addRequestBody:[@"add message" dataUsingEncoding:NSUTF8StringEncoding]
//                   headers:@{@"h":@"test", @"ua": @"request ua"}
//                 onSuccess:^(NSData * data) {
//      NSLog(@"%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
//    }
//                  onFailed:^(NSString * error) {
//      NSLog(@"%@", error);
//    }
//                onComplete:^{
//      NSLog(@"add message complete");
//    }];
//    
//    [[NSRunLoop mainRunLoop]run];
//    [net close];
  }
    return 0;
}
