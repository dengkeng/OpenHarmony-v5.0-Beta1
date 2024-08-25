# SERVICE框架生成工具IntelliJ插件说明(暂不支持)

## 简介

SERVICE框架生成工具，根据用户提供的.h头文件，工具会自动生成整个Service框架的代码。目前工具支持可执行文件、VS Code插件、IntelliJ插件三种入口，本文主要介绍IntelliJ插件使用说明。

## 目录 

	├── service                       # SERVICE框架生成工具
	│   ├── ...                       # 其他文件
	│   ├── service_IntelliJ_plugin   # IntelliJ插件代码
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

[工具使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/service/service_IntelliJ_plugin/docs/INSTRUCTION_ZH.md)

### 工具输出

根据使用者指定的.h头文件，工具会输出SERVICE框架代码。为了方便使用者快速上手工具，可供测试的.h文件内容如下所示：

```

	#ifndef EXAM_H
	#define EXAM_H
	using namespace std;

	namespace OHOS{
    	namespace Example{
        	class Exam{
        	public:
            	std::string getServName();
            	int32_t doSum(int32_t num1, int32_t num2);
        	};
    	}
	} 
	#endif
```

在window环境下的，根据输入.h文件生成的输出文件，如下所示：

![](../figures/service_framework.png)

## 开发说明

### 对象

工具的开发者

### 开发场景

若当前工具的功能已经不能满足开发者的全部需求，则开发者可以基于已有的源码对工具进行二次开发，来增强工具的能力，编译打包生成自定义的可执行文件和插件。
       
### 开发步骤

开发者可以根据如下的步骤来完成对工具IntelliJ插件的开发：

[工具开发说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/service/service_IntelliJ_plugin/docs/DEVELOP_ZH.md)

## FAQ

对于常见问题解决方法指导如下：

[FAQ](https://gitee.com/openharmony/napi_generator/tree/master/hdc/service/FAQ.md)

## 相关仓

暂无