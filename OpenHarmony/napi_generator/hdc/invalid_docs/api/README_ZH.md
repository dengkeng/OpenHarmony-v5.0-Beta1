# API扫描工具

## 简介

本文主要介绍API扫描工具，它可以扫描三方库中包含OpenHarmony源码不包含的接口，并输出result.xlsx文档。开发者移植三方库到OpenHarmony源码中，若三方库中包含一些OpenHarmony中不存在的接口，便会增加移植难度。此时可使用API扫描工具，提前预知风险接口，降低移植难度，提高开发效率。目前工具支持可执行文件、VS Code插件、IntelliJ插件三种入口。

更多工具的架构和实现原理详情，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/api/docs/INSTRUCTION_ZH.md)

	├── napi_generator                           # NAPI框架代码生成工具
	│   ├── ...                                  # 其他文档
	│   ├── hdc
	│   │   ├── ...                              # 其他工具
	│   │   ├── api                              # api扫描工具
	│   │   |   ├── api_scan_vs_plugin           # VS Code插件源码
	│   │   |   ├── api_scan_IntelliJ_plugin     # Intellij插件源码
	│   │   |   ├── src                          # 工具源码
	│   │   |   |   ├── scan.js                  # 工具源码入口
	│   │   |   |   ├── package.json             # package.json文件

## 约束
系统：建议Ubuntu 20.04或者Windows 10

依赖版本：VS Code 1.62.0

## 使用方法

### 使用对象

系统开发者
       
### 使用场景

移植三方库到OpenHarmony前预知风险接口。

### 工具使用

工具有三种类型，分别是可执行文件、VS Code插件、IntelliJ插件。其中的可执行文件可根据工具使用者的开发环境选择，支持Windows，Linux和Mac。可执行文件、IntelliJ插件、VS Code插件下载路径如下：

待增加链接

具体的工具使用步骤，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/api/docs/INSTRUCTION_ZH.md)

### 工具输出

根据使用者指定三方库项目源码，工具会输出风险接口。为了方便使用者快速上手工具，此处使用opencv项目为例，项目目录如下：

![](./figures/opencv.png)

在window环境下的，根据输入三方库项目,生成的输出文件result.xlsx，如下所示：

![](./figures/opencv_result.png)

其中生成的result.xlsx文件，风险接口如下所示：

![](./figures/opencv_include.png)

![](./figures/opencv_h.png)

## 工具开发说明

### 对象

工具的开发者

### 开发场景

若当前工具的功能已经不能满足开发者的全部需求，则开发者可以基于已有的源码对工具进行二次开发，来增强工具的能力，编译打包生成自定义的可执行文件和插件。

### 开发步骤

开发者可以根据如下的步骤来完成对工具的开发：

 [工具开发说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/api/docs/DEVELOP_ZH.md)

## 版本说明

暂无

## FAQ

  [FAQ](https://gitee.com/openharmony/napi_generator/tree/master/hdc/api/FAQ.md)

## 参与贡献

暂无

## 相关仓

暂无
