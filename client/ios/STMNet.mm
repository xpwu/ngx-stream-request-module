//
//  STMNet.m
//  ios-sdk
//
//  Created by xpwu on 2016/11/23.
//  Copyright © 2016年 xpwu.xpwu. All rights reserved.
//

#import "STMNet.h"
#include <list>

//https://developer.apple.com/library/content/qa/qa1652/_index.html
@implementation NSStream(StreamsToHost)

+ (void)getStreamsToHostNamed:(NSString *)hostName
                         port:(UInt16)port
                  inputStream:(out NSInputStream **)inputStreamPtr
                 outputStream:(out NSOutputStream **)outputStreamPtr
{
  CFReadStreamRef readStream = NULL;
  CFWriteStreamRef writeStream = NULL;
  
  CFStreamCreatePairWithSocketToHost(NULL
                                     , (__bridge CFStringRef) hostName
                                     , port
                                     , ((inputStreamPtr  != NULL) ? &readStream : NULL)
                                     , ((outputStreamPtr != NULL) ? &writeStream : NULL)
                                     );
  
  if (inputStreamPtr != NULL) {
    *inputStreamPtr  = CFBridgingRelease(readStream);
  }
  
  if (outputStreamPtr != NULL) {
    *outputStreamPtr = CFBridgingRelease(writeStream);
  }
}

@end

#pragma mark - Buffer

@interface Buffer : NSObject
@property(nonatomic) NSData* data;
@property(nonatomic) NSInteger pos;
@property(nonatomic) NSInteger last;

+(instancetype)nullBuffer;
+(instancetype)bufferWithData:(NSData*)data;
+(instancetype)bufferWithBytes:(const void *)data length:(NSUInteger)len;
+(instancetype)bufferWithBytesNoCopy:(nonnull void *)data length:(NSUInteger)len;
@end

@implementation Buffer
+(instancetype)nullBuffer {
  Buffer* buffer = [[Buffer alloc]init];
  buffer.data = nil;
  buffer.pos = 0;
  buffer.last = 0;
  return buffer;
}
+(instancetype)bufferWithData:(NSData*)data {
  Buffer* buffer = [[Buffer alloc]init];
  buffer.data = data;
  buffer.pos = 0;
  buffer.last = data.length;
  return buffer;
}
+(instancetype)bufferWithBytes:(const void *)data length:(NSUInteger)len {
  Buffer* buffer = [[Buffer alloc]init];
  buffer.data = [NSData dataWithBytes:data length:len];;
  buffer.pos = 0;
  buffer.last = len;
  return buffer;
}
+(instancetype)bufferWithBytesNoCopy:(nonnull void *)data length:(NSUInteger)len {
  Buffer* buffer = [[Buffer alloc]init];
  buffer.data = [NSData dataWithBytesNoCopy:data length:len];;
  buffer.pos = 0;
  buffer.last = len;
  return buffer;
}
@end

#pragma mark - STMNet

typedef enum{
  ReadStatusNext,
  ReadStatusAgain,
  ReadStatusError
} ReadStatus;

@interface ReadStatusWrapper : NSObject
@property(nonatomic) ReadStatus status;
+(instancetype)withStatus:(ReadStatus)st;
@end
@implementation ReadStatusWrapper
+(instancetype)withStatus:(ReadStatus)st {
  ReadStatusWrapper* wr = [[ReadStatusWrapper alloc]init];
  wr.status = st;
  return wr;
}
@end


@interface STMNet () {
  NSString* host_;
  UInt16 port_;
  
  NSInputStream* input_;
  NSOutputStream* output_;

  std::list<Buffer*> datas_;
  
  char lengthLen_;
  uint32_t length_;
  uint32_t messageLast_;
  uint8_t* message_;
  SEL method_;
  
  NSInteger openCnt_;
  
  NSTimer* inputTimer_;
  NSTimer* outputTimer_;
}
-(ReadStatusWrapper*)readLength;
-(ReadStatusWrapper*)readContent;

-(void)receive;
-(void)send;

-(void)reset;

-(void)connectTimeout;
-(void)inputTimeout;
-(void)outputTimeout;
-(void)hearbeat;

-(void)setInputTimer:(NSTimeInterval)interval action:(SEL)action;
-(void)setOutputTimer:(NSTimeInterval)interval action:(SEL)action;
-(void)invalidInputTimer;
-(void)invalidOutputTimer;

-(void)performOnCloseByLoop_:(id)str;
@end


/**
 *
 *  lencontent protocol:
 *
 *  1, handshake protocol:
 *
 *        client ------------------ server
 *          |                          |
 *          |                          |
 *        ABCDEF (A^...^F = 0xff) --->  check(A^...^F == 0xff) -N--> over
 *          |                          |
 *          |                          |Y
 *          |                          |
 *         data      <-------->       data
 *
 *
 *  2, data protocol:
 *     length | content
 *      length: 4 bytes, net order; length=sizeof(content)+4; length=0 => heartbeat
 *
 */

@implementation STMNet

-(instancetype)initWithHost:(NSString*)host andPort:(UInt16)port {
  if (self = [super init]) {
    self->host_ = host;
    self->port_ = port;
    input_ = nil;
    output_ = nil;
    openCnt_ = 0;
    
    message_ = nullptr;
    length_ = 0;
    messageLast_ = 0;
    lengthLen_ = 0;
    method_ = @selector(readLength);
    
    self->_status = STMNetStatusClosed;
    self.onopen = ^{NSLog(@"onopen");};
    self.onmessage = ^(NSData*){NSLog(@"onmessage");};
    self.onclose = ^(NSString* str){NSLog(@"%@",str);};
    
    inputTimer_ = nil;
    outputTimer_ = nil;
    
    self.hearbeatTime = 4*60;
    self.openTimeout = 30;
    self.transmissionTimeout = 10;
  }
  return self;
}

-(void)dealloc {
  [self close];
}

-(void)open {
  
  NSLog(@"open");
  
  if (((input_.streamStatus == NSStreamStatusOpening)
      || (input_.streamStatus == NSStreamStatusOpen))
      && ((output_.streamStatus == NSStreamStatusOpening)
          || (output_.streamStatus == NSStreamStatusOpen))) {
        return;
  }
  
  [self close];
  outputTimer_ = [NSTimer scheduledTimerWithTimeInterval:self.openTimeout
                                                  target:self
                                                selector:@selector(connectTimeout)
                                                userInfo:nil repeats:NO];
  
  NSInputStream* input;
  NSOutputStream* output;
  [NSStream getStreamsToHostNamed:host_ port:port_ inputStream:&input outputStream:&output];
  input_ = input;
  output_ = output;
  
  input_.delegate = self;
  output_.delegate = self;
  
  [input_ scheduleInRunLoop:[NSRunLoop currentRunLoop]
                    forMode:[NSRunLoop currentRunLoop].currentMode];
  [output_ scheduleInRunLoop:[NSRunLoop currentRunLoop]
                     forMode:[NSRunLoop currentRunLoop].currentMode];
  
  [input_ open];
  [output_ open];
  
  self->_status = STMNetStatusConnecting;
}

-(void)close {
  if (self.status == STMNetStatusOpen) {
    [input_ close];
    [output_ close];
  }
  
  openCnt_ = 0;
  self->_status = STMNetStatusClosed;
  
  [self reset];
}

-(void)send:(NSData*)data {
  uint32_t len = (uint32_t)data.length;
  len = htonl(len);
  datas_.push_back([Buffer bufferWithBytes:&len length:4]);
  
  datas_.push_back([Buffer bufferWithData:data]);
  
  [self send];
}

#pragma mark - NSStreamDelegate

- (void)stream:(NSStream *)theStream
   handleEvent:(NSStreamEvent)streamEvent {
   NSLog(@"%@, event=%ld", theStream == input_? @"input":@"output", streamEvent);
  switch (streamEvent) {
    case NSStreamEventOpenCompleted:
      openCnt_++;
      if (theStream == output_) {
        char *handshake = (char*)calloc(6, sizeof(char));
        handshake[5] = 0xff;
        for (int i = 0; i < 5; ++i) {
          handshake[5] ^= handshake[i];
        }
        datas_.push_back([Buffer bufferWithBytesNoCopy:handshake length:6]);
      }
      if (openCnt_ == 2) {
        [self setInputTimer:2*self.hearbeatTime action:@selector(inputTimeout)];
        [self setOutputTimer:self.hearbeatTime action:@selector(hearbeat)];
        self->_status = STMNetStatusOpen;
        self.onopen();
      }
      break;
    case NSStreamEventEndEncountered:
      self.onclose(@"connection closed by peer");
      [self close];
      break;
    case NSStreamEventErrorOccurred:
      self.onclose(@"connection error");
      [self close];
      break;
    case NSStreamEventHasBytesAvailable:
      [self receive];
      break;
    case NSStreamEventHasSpaceAvailable:
      [self send];
      break;
    default:
      break;
  }
}

#pragma mark - private

-(void)receive {
  [self invalidInputTimer];
  
  ReadStatusWrapper* st;
  do {
    st = ((ReadStatusWrapper* (*)(id, SEL))[self methodForSelector:method_])(self, method_);
//    st = [self performSelector:method_];
  } while (st.status == ReadStatusNext);
  
  if (st.status == ReadStatusError) {
    self.onclose(@"inputstream error");
    [self close];
    return;
  }
}

-(void)send {
  if (![output_ hasSpaceAvailable]) {
    return;
  }
  
  [self invalidOutputTimer];
  
  std::list<Buffer*>::iterator it = datas_.begin();
  for (; it != datas_.end(); ++it) {
    const uint8_t* p = (const uint8_t*)(*it).data.bytes;
    if (p == nil) {
      continue;
    }
    
    if (![output_ hasSpaceAvailable]) {
      break;
    }
    
    NSInteger n = [output_ write:p+(*it).pos maxLength:(*it).last-(*it).pos];
    if (n < 0) {
      STMNet* self_ = self;
      [[NSRunLoop currentRunLoop]performSelector:@selector(performOnCloseByLoop_:)
                                          target:self_
                                        argument:@"outputstream error"
                                           order:0
                                           modes:@[[NSRunLoop currentRunLoop].currentMode]];
      [self close];
      return;
    }
    
    (*it).pos += n;
    
    if ((*it).pos < (*it).last) {
      break;
    }
  }
  
  std::list<Buffer*>::iterator it2 = datas_.begin();
  while (it2 != it) {
    (*it2).data = nil;
    it2 = datas_.erase(it2);
  }
  
  if (datas_.empty()) {
    [self setOutputTimer:self.hearbeatTime action:@selector(hearbeat)];
  } else {
    [self setOutputTimer:self.transmissionTimeout action:@selector(outputTimeout)];
  }
}

-(ReadStatusWrapper*)readLength {
 
  if (!input_.hasBytesAvailable) {
    NSTimeInterval time = (lengthLen_==0? 2*self.hearbeatTime : self.transmissionTimeout);
    [self setInputTimer:time action:@selector(inputTimeout)];
    return [ReadStatusWrapper withStatus:ReadStatusAgain];
  }
  
  NSLog(@"readLength");
  
  uint8_t* p = (uint8_t*)&length_;
  NSInteger n = [input_ read:p+lengthLen_ maxLength:4-lengthLen_];
  if (n < 0) {
    return [ReadStatusWrapper withStatus:ReadStatusError];
  }
  
  if (n == 0) { // end
    [self setInputTimer:2*self.hearbeatTime action:@selector(inputTimeout)];
    return [ReadStatusWrapper withStatus:ReadStatusAgain];
  }
  
  lengthLen_ += n;
  
  if (lengthLen_ < 4) {
    [self setInputTimer:self.transmissionTimeout action:@selector(inputTimeout)];
    return [ReadStatusWrapper withStatus:ReadStatusAgain];
  }
  
  lengthLen_ = 0;
  length_ = ntohl(length_);
  NSLog(@"length=%d", length_);
  if (length_ == 0) { // hearbeat
    NSLog(@"reveive hearbeat");
    return [ReadStatusWrapper withStatus:ReadStatusNext];
  }
  
  length_ -= 4;
  messageLast_ = 0;
  message_ = (uint8_t*)calloc(length_, sizeof(uint8_t));
  
  method_ = @selector(readContent);
  return [ReadStatusWrapper withStatus:ReadStatusNext];
}

-(ReadStatusWrapper*)readContent {
  NSLog(@"readContent");
  if (!input_.hasBytesAvailable) {
    [self setInputTimer:self.transmissionTimeout action:@selector(inputTimeout)];
    return [ReadStatusWrapper withStatus:ReadStatusAgain];
  }
  
  NSInteger n = [input_ read:message_+messageLast_ maxLength:length_-messageLast_];
  if (n < 0) {
    return [ReadStatusWrapper withStatus:ReadStatusError];
  }
  
  messageLast_ += n;
  
  if (messageLast_ < length_) {
    [self setInputTimer:self.transmissionTimeout action:@selector(inputTimeout)];
    return [ReadStatusWrapper withStatus:ReadStatusAgain];
  }
  
  messageLast_ = 0;
  method_ = @selector(readLength);
  
  self.onmessage([NSData dataWithBytesNoCopy:message_ length:length_]);
  message_ = nullptr;
  
  return [ReadStatusWrapper withStatus:ReadStatusNext];
}

-(void)reset {
  [input_ removeFromRunLoop:[NSRunLoop currentRunLoop]
                    forMode:[NSRunLoop currentRunLoop].currentMode];
  [output_ removeFromRunLoop:[NSRunLoop currentRunLoop]
                     forMode:[NSRunLoop currentRunLoop].currentMode];
  
  input_ = nil;
  output_ = nil;
  openCnt_ = 0;
  
  message_ = nullptr;
  length_ = 0;
  messageLast_ = 0;
  lengthLen_ = 0;
  method_ = @selector(readLength);
  
  self->_status = STMNetStatusClosed;
  
  std::list<Buffer*>::iterator it = datas_.begin();
  for (; it != datas_.end(); ++it) {
    *it = nil;
  }
  datas_.clear();
  
  [self invalidInputTimer];
  [self invalidOutputTimer];
}

-(void)setInputTimer:(NSTimeInterval)interval action:(SEL)action {
  if ([inputTimer_ isValid]) {
    [inputTimer_ invalidate];
  }
  inputTimer_ = [NSTimer scheduledTimerWithTimeInterval:interval
                                                 target:self
                                               selector:action
                                               userInfo:nil repeats:NO];
}

-(void)setOutputTimer:(NSTimeInterval)interval action:(SEL)action {
  if ([outputTimer_ isValid]) {
    [outputTimer_ invalidate];
  }
  outputTimer_ = [NSTimer scheduledTimerWithTimeInterval:interval
                                                 target:self
                                               selector:action
                                               userInfo:nil repeats:NO];
}

-(void)invalidInputTimer {
  if ([inputTimer_ isValid]) {
    [inputTimer_ invalidate];
  }
  inputTimer_ = nil;
}

-(void)invalidOutputTimer {
  if ([outputTimer_ isValid]) {
    [outputTimer_ invalidate];
  }
  outputTimer_ = nil;
}

-(void)connectTimeout {
  self.onclose(@"connection timeout");
  [self reset];
}

-(void)inputTimeout {
  self.onclose(@"inputstream timeout");
  [self close];
}

-(void)outputTimeout {
  self.onclose(@"outputstream timeout");
  [self close];
}

-(void)hearbeat {
  uint32_t len = 0;
  datas_.push_back([Buffer bufferWithBytes:&len length:4]);
  [self send];
  NSLog(@"hearbeat");
}

-(void)performOnCloseByLoop_:(id)str {
  NSString* string = str;
  self.onclose(string);
}

@end
