
let stm = require("../stm/client.js");


// /pages/index.js
Page({
  data:{},
  onLoad:function(options){
    // 页面初始化 options为页面跳转所带来的参数
  },
  onReady:function(){
    // 页面渲染完成
    getApp().client.addRequest("test", function (data) {
      console.log(new stm.Client.StringView(data).toString());
    }, null, function (res) {
      console.error(res);
    }, function () {
      console.log("complete");
    });
  },
  onShow:function(){
    // 页面显示
  },
  onHide:function(){
    // 页面隐藏
  },
  onUnload:function(){
    // 页面关闭
  }
})