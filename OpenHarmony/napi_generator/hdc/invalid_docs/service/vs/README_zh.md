# SERVICE框架生成工具VS code插件说明

## 简介

SERVICE框架生成工具，根据用户提供的.h头文件，工具会自动生成整个Service框架的代码。目前工具支持可执行文件、VS Code插件两种入口，本文主要介绍VS Code插件使用说明。

## 目录 

	├── service                       # SERVICE框架生成工具
	│   ├── ...                       # 其他文件
	│   ├── service_vs_plugin         # VS Code插件代码
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

开发者为OpenHarmony系统框架开发某些功能，并将该功能包装成一个独立的服务进程运行在系统中。

### 工具使用

插件下载路径如下:

待增加链接

具体的工具使用步骤，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/service/service_vs_plugin/docs/INSTRUCTION_ZH.md)

### 工具输出

根据使用者指定的.h头文件，工具会输出SERVICE框架代码。为了方便使用者快速上手工具，可供测试的.h文件如下所示：

[test.h](https://gitee.com/openharmony/napi_generator/tree/master/hdc/service/examples/test.h)

注意：.h文件中待生成的主class必须加注释：@brief service服务，提供IPC调用接口 ，如下所示：

```
/**
 * @brief service服务，提供IPC调用接口
 * @ServiceClass
 */
```

在window环境下的，根据输入.h文件生成的输出文件，如下所示：

![](../figures/service_framework.png)

## 开发说明

### 对象

工具的开发者

### 开发场景

若当前工具的功能已经不能满足开发者的全部需求，则开发者可以基于已有的源码对工具进行二次开发，来增强工具的能力，编译打包生成自定义的可执行文件和插件。
       
### 开发步骤

开发者可以根据如下的步骤来完成对工具VS Code插件的开发：

[工具开发说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/service/service_vs_plugin/docs/DEVELOP_ZH.md)

## FAQ

对于常见问题解决方法指导如下：

[FAQ](https://gitee.com/openharmony/napi_generator/tree/master/hdc/service/FAQ.md)

## 相关仓

暂无