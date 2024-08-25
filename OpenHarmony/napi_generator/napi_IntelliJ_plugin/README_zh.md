# NAPI框架生成工具IntelliJ插件说明

## 简介

NAPI框架代码生成工具，它可以根据用户指定路径下的ts(typescript)接口文件一键生成NAPI框架代码、业务代码框架、GN文件等。目前工具支持可执行文件、VS Code插件、DevEco Studio上使用的IntelliJ插件三种入口，本文主要介绍IntelliJ插件使用说明。

## 目录 

	├── napi_generator                # NAPI框架代码生成工具
	│   ├── ...                       # 其他文件
	│   ├── napi_IntelliJ_plugin      # IntelliJ插件代码
	│   │   ├── docs                  # IntelliJ插件说明
	│   │   ├── resources             # IntelliJ插件说明
	│   │   ├── src    				  # IntelliJ插件源码
	│   │   └── README_zh             # IntelliJ插件说明

## 约束 

系统：建议Windows 10

依赖版本：JDK 11

开发工具：DevEco stdio、IDEA Community 2021.3.3

## 使用方法 

### 使用对象

系统开发者

### 使用场景

1) 系统框架层新增子系统，需对应用层提供接口。
2) 系统框架层子系统能力增强后，需对应用层提供新接口。

### 工具使用

插件下载路径如下，选择新版本下载。

[DevEco Studio上使用的IntelliJ插件下载链接](https://plugins.jetbrains.com/plugin/19593-napi-generator/versions)

![](../figures/picGoogle-napi_jar_download.png)

具体的工具使用步骤，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/tree/master/napi_IntelliJ_plugin/docs/napi/INSTRUCTION_ZH.md)

### 工具输出

根据使用者指定的typescript文件，工具会输出NAPI框架代码、业务代码框架、GN脚本等文件。

为了方便使用者快速上手工具，可供测试的typescript文件存放在DevEco Studio中以下路径：

```
entry/src
```

在window环境下的，根据输入文件@ohos.napitest.d.ts和basic.d.ts生成的输出文件，如下所示：

![](../figures/pic-d-ts-dev_transition.png)



其中CMakeLists.txt为编译构建需要的文件，cfg.json为生成的业务代码配置文件，若用户不进行业务代码配置，则不会生成该文件；生成的"napitest.h"文件，定义了框架代码的接口，生成的部分接口如下所示：

```
...
class NodeISayHello {
public:
    bool addSayHelloListener(NodeISayHelloListener& listener);
    static NodeISayHelloListener listener_;
    bool removeSayHelloListener(NodeISayHelloListener& listener);
    bool registerCallbackfunc();
    // 供业务调用的回调接口
    void CallbackfuncCallback(NUMBER_TYPE_2& wid);

    bool unRegisterCallbackfunc();
    bool sayHello(std::string& from, std::string& to, NUMBER_TYPE_9& sayType);
    bool sayHi(std::string& from, std::string& to, NUMBER_TYPE_10& sayType);
    bool sayHelloWithResponse(std::string& from, std::string& to, NUMBER_TYPE_11& sayType, uint32_t& outErrCode, AUTO_INTERFACE_5& out);
    static AUTO_INTERFACE_5 auto_interface_5OutRes;
    void auto_interface_5SetCbValue(NUMBER_TYPE_6 result, std::string errMsg, std::string response);
};
...
```

## 开发说明

### 对象

工具的开发者

### 开发场景

若当前工具的功能已经不能满足开发者的全部需求，则开发者可以基于已有的源码对工具进行二次开发，来增强工具的能力，编译打包生成自定义的可执行文件和插件。
       
### 开发步骤

开发者可以根据如下的步骤来完成对DevEco Studio上使用的工具IntelliJ插件的开发：

 [工具开发说明](https://gitee.com/openharmony/napi_generator/tree/master/napi_IntelliJ_plugin/docs/napi/DEVELOP_ZH.md)
    
## 版本说明 

当前版本已支持的特性和待开发的特性，如下所示：

 [已支持特性](https://gitee.com/openharmony/napi_generator/blob/master/release-notes)

 [待支持特性](https://gitee.com/openharmony/napi_generator/blob/master/docs/guide/ROADMAP_ZH.md)

## FAQ

对于常见问题解决方法指导如下：

  [FAQ](https://gitee.com/openharmony/napi_generator/blob/master/FAQ.md)

## 相关仓

暂无