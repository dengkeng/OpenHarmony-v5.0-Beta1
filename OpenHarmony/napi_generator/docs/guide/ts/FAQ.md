# Ts接口生成工具 问题反馈

## 问题反馈

1、使用工具转换.h文件时报错，显示header_parser.exe文件有误。

![](../../../figures/header_parser_not_exist.png)

问题定位：使用可执行程序转换.h文件时，当前路径下没有header_parser.exe文件，导致转换失败。

问题解决：下载header_parser.exe文件，并放置在napi_generator-win.exe、待转换.h文件相同路径下，即可解解决以上问题。

