//
//  STMClient.m
//  ios-sdk
//
//  Created by xpwu on 2016/11/24.
//  Copyright © 2016年 xpwu.xpwu. All rights reserved.
//

#import "STMClient.h"
#import "STMNet.h"
#import "STMDefaultContentProtocol.h"
#import "Log.h"

const uint32_t reqIDstart = 200;
const uint32_t blockID = reqIDstart-1;
const uint32_t pushID = 1; // need equal server

@interface Request : NSObject
@property(nonatomic) uint32_t reqID;
@property(nonatomic) NSData* body;
@property(nonatomic) NSDictionary<NSString*, NSString*>* headers;
@property(nonatomic) void (^suc)(NSData*);
@property(nonatomic) BOOL (^sucOnlyForBlock)(NSData*);
@property(nonatomic) void (^failed)(NSString*);
@property(nonatomic) void (^complete)();
@end

@implementation Request @end

@interface STMClient () {
  STMNet* net_;
  NSMutableDictionary<NSNumber*, Request*>* requests_;
  id<STMContentProtocol> protocol_;
  Request* blockRequest_;
  BOOL isBlock_;
  
  uint32_t reqID_;
  
  void (^onConnectionSuc_)(void);
  void (^onConnectionFaild_)(NSString*);
  
  void (^normalOnMessage_)(NSData*);
  
  NSTimeInterval ctime_;
  NSTimeInterval htime_;
  NSTimeInterval ttime_;
}
-(uint32_t)reqID;
-(void)connect;
-(void)postMessage:(void(^)(void))message;
-(void)performMessageByRunLoop_:(id)message;
-(void)sendBlockRequest;
-(void)sendAllRequests;
-(void)setOnMessageToNormal;
-(void)setBlock:(BOOL)block;
-(void)sendRequest:(NSData*)body
        withHeader:(NSDictionary<NSString*, NSString*>*)header
          andReqID:(uint32_t)reqid;
-(void)errorAllRequests:(NSString*)error;
@end

@implementation STMClient
-(instancetype)init {
  if (self = [super init]) {
    reqID_ = reqIDstart;
    net_ = nil;
    protocol_ = [[STMDefaultContentProtocol alloc]init];
    isBlock_ = NO;
    self.onpush = ^(NSData* data){NSLog(@"receive push data");};
    requests_ = [[NSMutableDictionary alloc]init];
    
    ctime_ = 30;
    htime_ = 4*60;
    ttime_ = 10;
  }
  return self;
}

-(void)dealloc {
  [net_ close];
}

-(void)setConfigConnectionTimeout:(NSTimeInterval)ctime
                        heartbeat:(NSTimeInterval)htime
                     transmission:(NSTimeInterval)ttime {
  ctime_ = ctime;
  htime_ = htime;
  ttime_ = ttime;
}

-(void)setConnectHost:(NSString*)host
                 port:(uint16_t)port {
  [self setConnectHost:host port:port onSuccess:nil onFailed:nil];
}

-(void)setConnectHost:(NSString*)host
                 port:(uint16_t)port
            onSuccess:(void (^)(void))suc {
  [self setConnectHost:host port:port onSuccess:suc onFailed:nil];
}

-(void)setConnectHost:(NSString*)host
                 port:(uint16_t)port
            onSuccess:(void (^)(void))suc
             onFailed:(void (^)(NSString*))failed {
  net_ = [[STMNet alloc]initWithHost:host andPort:port];
  onConnectionSuc_ = suc;
  onConnectionFaild_ = failed;
  net_.hearbeatTime = htime_;
  net_.transmissionTimeout = ttime_;
  net_.openTimeout = ctime_;
}

-(void)setBlockRequestOnConnected:(NSData*)body
                        onSuccess:(BOOL (^)(NSData*))suc {
  [self setBlockRequestOnConnected:body
                           headers:nil onSuccess:suc
                          onFailed:nil onComplete:nil];
}

-(void)setBlockRequestOnConnected:(NSData*)body
                          headers:(NSDictionary<NSString*, NSString*>*)headers
                        onSuccess:(BOOL (^)(NSData*))suc {
  [self setBlockRequestOnConnected:body
                           headers:headers onSuccess:suc
                          onFailed:nil onComplete:nil];
}

-(void)setBlockRequestOnConnected:(NSData*)body
                          headers:(NSDictionary<NSString*, NSString*>*)headers
                        onSuccess:(BOOL (^)(NSData*))suc
                         onFailed:(void (^)(NSString*))failed {
  [self setBlockRequestOnConnected:body
                           headers:headers onSuccess:suc
                          onFailed:failed onComplete:nil];
}

-(void)setBlockRequestOnConnected:(NSData*)body
                          headers:(NSDictionary<NSString*, NSString*>*)headers
                        onSuccess:(BOOL (^)(NSData*))suc
                         onFailed:(void (^)(NSString*))failed
                       onComplete:(void (^)())complete {
  blockRequest_ = [[Request alloc]init];
  blockRequest_.body = body;
  blockRequest_.headers = headers;
  blockRequest_.sucOnlyForBlock = suc;
  blockRequest_.failed = failed;
  blockRequest_.complete = complete;
  blockRequest_.reqID = blockID;
}



-(void)addRequestBody:(NSData*)body
            onSuccess:(void (^)(NSData*))suc {
  [self addRequestBody:body headers:nil onSuccess:suc onFailed:nil onComplete:nil];
}

-(void)addRequestBody:(NSData*)body
              headers:(NSDictionary<NSString*, NSString*>*)headers
            onSuccess:(void (^)(NSData*))suc {
  [self addRequestBody:body headers:headers onSuccess:suc onFailed:nil onComplete:nil];
}

-(void)addRequestBody:(NSData*)body
              headers:(NSDictionary<NSString*, NSString*>*)headers
            onSuccess:(void (^)(NSData*))suc
             onFailed:(void (^)(NSString*))failed {
  [self addRequestBody:body headers:headers onSuccess:suc onFailed:failed onComplete:nil];
}

-(void)addRequestBody:(NSData*)body
              headers:(NSDictionary<NSString*, NSString*>*)headers
            onSuccess:(void (^)(NSData*))suc
             onFailed:(void (^)(NSString*))failed
           onComplete:(void (^)())complete {
  if (net_ == nil) {
    if (complete != nil) {
      complete();
    }
    if (failed != nil) {
      failed(@"host and port not set!");
    }
    return;
  }
  
  uint32_t reqid = [self reqID];
  Request* req = [[Request alloc]init];
  req.body = body;
  req.headers = headers;
  req.suc = suc;
  req.failed = failed;
  req.complete = complete;
  req.reqID = reqid;
  
  [requests_ setObject:req forKey:[NSNumber numberWithInt:reqid]];
  
  if (isBlock_) {
    return;
  }
  if (net_.status == STMNetStatusOpen) {
    [self sendRequest:body withHeader:headers andReqID:reqid];
    return;
  }
  if (net_.status == STMNetStatusConnecting) {
    return;
  }
  [self connect];
}

#pragma mark - private

-(uint32_t)reqID {
  reqID_ = reqID_+1;
  
  if (reqID_ < reqIDstart) {
    reqID_ = reqIDstart;
  }
  
  return reqID_;
}

#define defineWEAK(arg) __weak __typeof(arg) _weak_##arg = arg
#define defineWEAK_TYPE(type, arg) type _weak_##arg = arg
#define weak(arg) _weak_##arg

-(void)connect {
  defineWEAK(protocol_);
  defineWEAK(self);
  defineWEAK(requests_);
  
  normalOnMessage_ = ^(NSData* data){
    STMResponse* response = [weak(protocol_) parse:data];
    
    if (response.reqID == pushID) {
      weak(self).onpush(response.data);
      return;
    }
    
    Request* request = [weak(requests_) objectForKey:[NSNumber numberWithInt:response.reqID]];
    if (request == nil) {
      NSLog(@"error: not find request");
      return;
    }
    if (request.complete != nil) {
      request.complete();
    }
    if (response.status != STMResponseStatusSuccess
        && request.failed != nil) {
      if (response.data == nil) {
        request.failed(@"may be server error, but server has closed the error log");
      } else {
        request.failed([[NSString alloc] initWithData:response.data encoding:NSUTF8StringEncoding]);
      }
    }
    if (response.status == STMResponseStatusSuccess
        && request.suc != nil) {
      request.suc(response.data);
    }
    
    [weak(requests_) removeObjectForKey:[NSNumber numberWithInt:response.reqID]];
  };
  
  defineWEAK(onConnectionSuc_);
  
  net_.onopen = ^(){
    [weak(protocol_) onopen:^{
      if (blockRequest_ != nil) {
        [weak(self) sendBlockRequest];
      } else {
        [weak(self) sendAllRequests];
      }
    }];
    if (weak(onConnectionSuc_) != nil) {
      weak(onConnectionSuc_)();
    }
  };
  
  defineWEAK(onConnectionFaild_);
  defineWEAK_TYPE(BOOL, isBlock_);
  defineWEAK(net_);
  
  net_.onclose = ^(NSString* str){
    
    if (weak(isBlock_)) {
      weak(net_).onmessage([weak(protocol_) buildFailedMessage:str withReqid:blockID]);
    }
    
    [weak(self) errorAllRequests:str];
    
    if (weak(onConnectionFaild_) != nil) {
      weak(onConnectionFaild_)(str);
    }
  };
  
  net_.onmessage = normalOnMessage_;
  
  [net_ open];
}

-(void)postMessage:(void(^)(void))message {
  STMClient* __weak _self = self;
  [[NSRunLoop currentRunLoop]performSelector:@selector(performMessageByRunLoop_:)
                                      target:_self
                                    argument:message
                                       order:0
                                       modes:@[[NSRunLoop currentRunLoop].currentMode]];
}

-(void)performMessageByRunLoop_:(id)message {
  void(^msg)(void) = message;
  msg();
}

-(void)sendBlockRequest {
  defineWEAK(protocol_);
  defineWEAK(self);
  defineWEAK(blockRequest_);
  
  isBlock_ = YES;
  
  net_.onmessage = ^(NSData* data) {
    STMResponse* response = [weak(protocol_) parse:data];
 
    BOOL isSuc = YES;
    BOOL sendMore = YES;
    
    Request* request = weak(blockRequest_);
    if (request.complete != nil) {
      request.complete();
    }
    if (response.status != STMResponseStatusSuccess) {
      isSuc = NO;
    }
    if (response.status != STMResponseStatusSuccess
        && request.failed != nil) {
      if (response.data == nil) {
        request.failed(@"may be server error, but server has closed the error log");
      } else {
        request.failed([[NSString alloc] initWithData:response.data encoding:NSUTF8StringEncoding]);
      }
    }
    if (response.status == STMResponseStatusSuccess
        && request.sucOnlyForBlock != nil) {
      sendMore = request.sucOnlyForBlock(response.data);
    }
    
    sendMore = sendMore && isSuc;
    
    if (!isSuc) {
      [weak(self) errorAllRequests:[@"block request error---" stringByAppendingString:[[NSString alloc] initWithData:response.data encoding:NSUTF8StringEncoding]]];
    }
    
    if (sendMore) {
      [weak(self) sendAllRequests];
    } else if (isSuc) {
      [weak(self) errorAllRequests:@"block request stop this request continuing"];
    }
    
    [weak(self) setOnMessageToNormal];
    [weak(self) setBlock:NO];
  };
  
  [self sendRequest:blockRequest_.body
         withHeader:blockRequest_.headers
           andReqID:blockRequest_.reqID];
  
}

-(void)sendAllRequests {
  defineWEAK(self);
  
  [requests_ enumerateKeysAndObjectsUsingBlock:^(NSNumber * _Nonnull key
                                                 , Request * _Nonnull obj
                                                 , BOOL * _Nonnull stop) {
    [weak(self) sendRequest:obj.body withHeader:obj.headers andReqID:obj.reqID];
  }];
}

-(void)setOnMessageToNormal {
  net_.onmessage = normalOnMessage_;
}

-(void)setBlock:(BOOL)block {
  isBlock_ = block;
}

-(void)sendRequest:(NSData*)body
        withHeader:(NSDictionary<NSString*, NSString*>*)header
          andReqID:(uint32_t)reqid {
  
  NSData* data = [protocol_ build:body
                      withHeaders:header
                        withReqID:reqid];
  
  if (data == nil) {
    [self postMessage:^{
      net_.onmessage([protocol_ buildFailedMessage:@"build message error, maybe length of headers' key or value > 255, or is not asscii"
                                         withReqid:reqid]);
    }];
    return;
  }
  
  [net_ send:data];
}

-(void)errorAllRequests:(NSString*)error {
  [requests_ enumerateKeysAndObjectsUsingBlock:^(NSNumber * _Nonnull key
                                                 , Request * _Nonnull obj
                                                 , BOOL * _Nonnull stop) {
    normalOnMessage_([protocol_ buildFailedMessage:error
                                         withReqid:[key intValue]]);
  }];
  
  [requests_ removeAllObjects];
}

@end




