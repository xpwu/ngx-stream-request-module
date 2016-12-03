//
//  STMClient.h
//  ios-sdk
//
//  Created by xpwu on 2016/11/24.
//  Copyright © 2016年 xpwu.xpwu. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface STMClient : NSObject

@property(nonatomic) void (^onpush)(NSData*);

// unit: s
// default  30s; 4*60s; 10s
-(void)setConfigConnectionTimeout:(NSTimeInterval)ctime_s
                        heartbeat:(NSTimeInterval)htime_s
                     transmission:(NSTimeInterval)ttime_s;


-(void)setConnectHost:(NSString*)host
                 port:(uint16_t)port;

-(void)setConnectHost:(NSString*)host
                 port:(uint16_t)port
            onSuccess:(void (^)(void))suc;

-(void)setConnectHost:(NSString*)host
                 port:(uint16_t)port
            onSuccess:(void (^)(void))suc
             onFailed:(void (^)(NSString*))failed;



/**
 All args can be set nil;
 onSuccess: only callback for successful. return YES: continue else request. NO, stop
 onFailed: only callback for failed
 complete: callback wether successful or failed
 */

-(void)setBlockRequestOnConnected:(NSData*)body
                        onSuccess:(BOOL (^)(NSData*))suc;

-(void)setBlockRequestOnConnected:(NSData*)body
                          headers:(NSDictionary<NSString*, NSString*>*)headers
                        onSuccess:(BOOL (^)(NSData*))suc;

-(void)setBlockRequestOnConnected:(NSData*)body
                          headers:(NSDictionary<NSString*, NSString*>*)headers
                        onSuccess:(BOOL (^)(NSData*))suc
                         onFailed:(void (^)(NSString*))failed;

-(void)setBlockRequestOnConnected:(NSData*)body
                          headers:(NSDictionary<NSString*, NSString*>*)headers
                        onSuccess:(BOOL (^)(NSData*))suc
                         onFailed:(void (^)(NSString*))failed
                       onComplete:(void (^)())complete;


/**
 All args can be set nil;
 onSuccess: only callback for successful.
 onFailed: only callback for failed
 complete: callback wether successful or failed
 */

-(void)addRequestBody:(NSData*)body
            onSuccess:(void (^)(NSData*))suc;

-(void)addRequestBody:(NSData*)body
              headers:(NSDictionary<NSString*, NSString*>*)headers
            onSuccess:(void (^)(NSData*))suc;

-(void)addRequestBody:(NSData*)body
              headers:(NSDictionary<NSString*, NSString*>*)headers
            onSuccess:(void (^)(NSData*))suc
             onFailed:(void (^)(NSString*))failed;

-(void)addRequestBody:(NSData*)body
              headers:(NSDictionary<NSString*, NSString*>*)headers
            onSuccess:(void (^)(NSData*))suc
             onFailed:(void (^)(NSString*))failed
           onComplete:(void (^)())complete;

@end
