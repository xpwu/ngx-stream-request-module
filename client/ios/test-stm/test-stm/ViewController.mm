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
}

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
  // Do any additional setup after loading the view, typically from a nib.
  client = [[STMClient alloc]init];
  [client setConnectHost:@"127.0.0.1" port:8000
               onSuccess:^{
                 NSLog(@"connect successful");
               }
                onFailed:^(NSString * error) {
                  NSLog(@"%@", error);
                }];
  
  client.onpush = ^(NSData* data) {
    NSLog(@"[push]---%@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  };
  
  [client addRequestBody:[@"flajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflaflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklf" dataUsingEncoding:NSUTF8StringEncoding] headers:@{@"api": @"/api/ServerInfo"} onSuccess:^(NSData * data) {
    NSLog(@"success, %@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  } onFailed:^(NSString * str) {
    NSLog(@"%@", str);
  } onComplete:^{
    NSLog(@"complete");
  }];
  
  [client addRequestBody:[@"flajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflaflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklf" dataUsingEncoding:NSUTF8StringEncoding] headers:@{@"api": @"/api/php/info"} onSuccess:^(NSData * data) {
    NSLog(@"success, %@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  } onFailed:^(NSString * str) {
    NSLog(@"%@", str);
  } onComplete:^{
    NSLog(@"complete");
  }];
}

- (void)didReceiveMemoryWarning {
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}

-(IBAction)selector:(id)sender {
  [client addRequestBody:[@"flajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflaflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklfjsdklflajsfjklsdfjklasdklf" dataUsingEncoding:NSUTF8StringEncoding] headers:@{@"api": @"/api/php/info"} onSuccess:^(NSData * data) {
    NSLog(@"success, %@", [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
  } onFailed:^(NSString * str) {
    NSLog(@"%@", str);
  } onComplete:^{
    NSLog(@"complete");
  }];
}

@end
