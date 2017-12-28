//
//  ViewController.m
//  test-stm
//
//  Created by xpwu on 2016/12/13.
//  Copyright © 2016年 xpwuxpwu. All rights reserved.
//

#import "ViewController.h"
//#import "../../out/STMClient.h"
#import "../../STMClient.h"

@interface ViewController () {
  STMClient* client;
  STMClient* client2;
}

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
  // Do any additional setup after loading the view, typically from a nib.
  client = [[STMClient alloc]init];
  client2 = [[STMClient alloc]init];
  
  [client setConnectHost:@"127.0.0.1" port:8000
               onSuccess:^{
                 NSLog(@"client1 connect successful");
               }
                onFailed:^(NSString * error) {
                  NSLog(@"client1 %@", error);
                }];
  [client2 setConnectHost:@"127.0.0.1" port:8002
               onSuccess:^{
                 NSLog(@"client2 connect successful");
               }
                onFailed:^(NSString * error) {
                  NSLog(@"client2 %@", error);
                }];
  
  client.onpush = ^(NSData* data) {
    NSLog(@"[client1 push]---%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  };
  
  client2.onpush = ^(NSData* data) {
    NSLog(@"[client2 push]---%@"
          , [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  };
  
  [client addRequestBody:[@"flajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflaflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklf" dataUsingEncoding:NSUTF8StringEncoding] headers:@{@"api": @"/api/ServerInfo"} onSuccess:^(NSData * data) {
    NSLog(@"client1 success, %@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  } onFailed:^(NSString * str) {
    NSLog(@"client1 %@", str);
  } onComplete:^{
    NSLog(@"client1 complete");
  }];
  
  [client addRequestBody:[@"flajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflaflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklf" dataUsingEncoding:NSUTF8StringEncoding] headers:@{@"api": @"/api/php/info"} onSuccess:^(NSData * data) {
    NSLog(@"client1 success, %@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  } onFailed:^(NSString * str) {
    NSLog(@"client1 %@", str);
  } onComplete:^{
    NSLog(@"client1 complete");
  }];
  
  [client2 addRequestBody:[@"client2" dataUsingEncoding:NSUTF8StringEncoding] headers:@{@"api": @"api/php/info"} onSuccess:^(NSData * data) {
    NSLog(@"client2 success, %@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  } onFailed:^(NSString * str) {
    NSLog(@"client2 %@", str);
  } onComplete:^{
    NSLog(@"client2 complete");
  }];
}

- (void)didReceiveMemoryWarning {
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}

-(IBAction)selector:(id)sender {
  [client addRequestBody:[@"flajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflaflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklf" dataUsingEncoding:NSUTF8StringEncoding] headers:@{@"api": @"/api/php/info"} onSuccess:^(NSData * data) {
    NSLog(@"client1 success, %@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  } onFailed:^(NSString * str) {
    NSLog(@"client1 %@", str);
  } onComplete:^{
    NSLog(@"client1 complete");
  }];
  
  
  [client2 addRequestBody:[@"client2" dataUsingEncoding:NSUTF8StringEncoding] headers:@{@"api": @"api/php/info"} onSuccess:^(NSData * data) {
    NSLog(@"client2 success, %@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  } onFailed:^(NSString * str) {
    NSLog(@"client2 %@", str);
  } onComplete:^{
    NSLog(@"client2 complete");
  }];
  
}

@end
