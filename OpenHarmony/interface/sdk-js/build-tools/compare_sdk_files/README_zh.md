# ohos-sdk 两个版本文件比对工具

## 简介
比对两个ohos-sdk版本，将两个版本相同平台的共同文件以及缺失文件输出到Excel表格中

## 目录

```
├─src         #存放源码
└─test        #本地运行使用文件
```

## 环境

电脑中必须配置有Python环境

## 打包

1、工具代码clone下来之后，需要在当前工程目录下安装打包依赖，即在 .\build-tools\compare_sdk_files 目录下进入终端，输入命令：pip install pyinstaller

2、打包依赖安装完成之后，输入打包命令：pyinstaller --onefile .\src\main.py

3、工具打包完成之后，会在当前工程文件下生成'build'文件夹、'dist'文件夹、main.spec文件，工具包为'dist'文件夹下的'main.exe'文件

## 运行

在'dist'文件夹下进入终端，运行以下命令即可运行工具

```
main.exe -N compare -P 旧版SDK路径(确定到平台) -M 新版SDK路径(确定到平台) -O 输出文件差异结果Excel表格地址

例如：main.exe -N compare -P E:\3.2.3.0\ohos-sdk\linux -M E:\3.2.6.3\ohos-sdk\linux -O E:\diff.xlsx
```

> **说明：**
> 
> 1、需保证参数按照规定顺序输入
> 
> 2、旧版本SDK和新版本SDK路径必须确定在ohos-sdk目录下的linux、windows或者mac文件夹，各平台内压缩包无需手动解压
> 
> 3、输出地址如果只填写文件路径未指定具体的输出文件名，则会在指定文件目录下输出'diff.xlsx'文件，也可将文件名拼接至输出路径中
> 
