# API扫描工具VS code插件说明

## 简介

API扫描工具，它可以根据用户给定三方库项目扫描输出风险接口以及.h头文件。目前工具支持可执行文件、VS Code插件、IntelliJ插件三种入口，本文主要介绍VS Code插件使用说明。

## 目录 

	├── api                           # API扫描工具
	│   ├── ...                       # 其他文件
	│   ├── api_scan_vs_plugin        # VS Code插件代码
	│   │   ├── docs                  # VS Code插件说明
	│   │   ├── src    				  # VS Code插件源码
	│   │   ├── package.json    	  # package.json 文件
	│   │   └── README_zh.md          # VS Code插件说明

## 约束 

系统：建议Ubuntu 20.04或者Windows 10

依赖版本：VS Code 1.62.0

## 使用方法 

### 使用对象

系统开发者

### 使用场景

1)移植三方库到OpenHarmony前预知风险接口或.h头文件。

### 工具使用

插件下载路径如下:

待增加链接

具体的工具使用步骤，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/api/api_scan_vs_plugin/docs/INSTRUCTION_ZH.md)

### 工具输出

根据使用者指定三方库项目源码，工具会输出风险接口、.h头文件。为了方便使用者快速上手工具，此处使用opencv项目为例，项目目录如下：

![](../figures/opencv.png)

在window环境下的，根据输入三方库项目,生成的输出文件result.xlsx，如下所示：

![](../figures/opencv_result.png)

其中生成的result.xlsx文件，sheet1为风险接口，如下所示：

![](../figures/opencv_include.png)

sheet2为风险.h头文件，如下所示：

![](../figures/opencv_h.png)

## 开发说明

### 对象

工具的开发者

### 开发场景

若当前工具的功能已经不能满足开发者的全部需求，则开发者可以基于已有的源码对工具进行二次开发，来增强工具的能力，编译打包生成自定义的可执行文件和插件。
       
### 开发步骤

开发者可以根据如下的步骤来完成对工具VS Code插件的开发：

[工具开发说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/api/api_scan_vs_plugin/docs/DEVELOP_ZH.md)

## FAQ

对于常见问题解决方法指导如下：

[FAQ](https://gitee.com/openharmony/napi_generator/tree/master/hdc/api/FAQ.md)

## 相关仓

暂无