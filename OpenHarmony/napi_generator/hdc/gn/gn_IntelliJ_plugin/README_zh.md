# GN脚本生成工具IntelliJ插件说明(暂不支持)

## 简介

GN脚本生成工具，它可以根据用户给定三方库项目的CMakeLists.txt文件，转换生成BUILD.gn文件。目前工具支持可执行文件、VS Code插件、IntelliJ插件三种入口，本文主要介绍IntelliJ插件使用说明。

## 目录 

	├── gn                            # GN脚本生成工具
	│   ├── ...                       # 其他文件
	│   ├── gn_IntelliJ_plugin        # IntelliJ插件代码
	│   │   ├── docs                  # IntelliJ插件说明
	│   │   ├── resources             # IntelliJ插件说明
	│   │   ├── src    				  # IntelliJ插件源码
	│   │   └── README_zh             # IntelliJ插件说明

## 约束 

系统：不限

依赖版本：JDK 11

开发工具：DevEco stdio、IDEA Community 2021.3.3

## 使用方法 

### 使用对象

系统开发者

### 使用场景

1)移植CMakeLists.txt编译方式的三方库到OpenHarmony源码中。

### 工具使用

插件下载路径如下:

[下载链接](暂无)

具体的工具使用步骤，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/gn/gn_IntelliJ_plugin/docs/INSTRUCTION_ZH.md)

### 工具输出

根据使用者指定三方库的CMakeLists.txt文件，工具会输出对应的BUILD.gn文件。为了方便使用者快速上手工具，可供测试的三方库项目目录如下：

	harmony@Ubuntu-64:~/OpenHarmony/third_party/test_project$ ls
	CMakeLists.txt  main.c

CMakeLists.txt文件内容如下：

	CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
	PROJECT(hello)
	AUX_SOURCE_DIRECTORY(. SRC_LIST)
	ADD_EXECUTABLE(hello ${SRC_LIST})

在linux环境下的，根据输入三方库项目的CMakeLists.txt文件,生成的输出文件，如下所示：

	harmony@Ubuntu-64:~/OpenHarmony/third_party/test_project$ ls
	build_tmp  CMakeLists.txt  main.c
	harmony@Ubuntu-64:~/OpenHarmony/third_party/test_project$ cd build_tmp/
	harmony@Ubuntu-64:~/OpenHarmony/third_party/test_project/build_tmp$ ls
	BUILD.gn  CMakeCache.txt  CMakeFiles  cmake_install.cmake  hello  Makefile  ohos.toolchain.cmake

其中生成的BUILD.gn文件，内容如下所示：

![](../figures/build_file.png)

## 开发说明

### 对象

工具的开发者

### 开发场景

若当前工具的功能已经不能满足开发者的全部需求，则开发者可以基于已有的源码对工具进行二次开发，来增强工具的能力，编译打包生成自定义的可执行文件和插件。
       
### 开发步骤

开发者可以根据如下的步骤来完成对工具IntelliJ插件的开发：

[工具开发说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/gn/gn_IntelliJ_plugin/docs/DEVELOP_ZH.md)

## FAQ

对于常见问题解决方法指导如下：

[FAQ](https://gitee.com/openharmony/napi_generator/tree/master/hdc/gn/FAQ.md)

## 相关仓

暂无