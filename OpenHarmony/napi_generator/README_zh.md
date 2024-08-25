# NAPI框架生成工具

## 简介
本文主要介绍NAPI框架代码生成工具，它可以根据用户指定路径下的ts(typescript)接口文件一键生成NAPI框架代码、业务代码框架、GN文件等。在开发JS应用与NAPI间接口时，底层框架开发者无需关注Nodejs语法、C++与JS之间的数据类型转换等上层应用转换逻辑，只关注底层业务逻辑即可，专业的人做专业的事，从而可以大大提高开发效率。目前工具支持可执行文件、VS Code插件、DevEco Studio上使用的IntelliJ插件三种入口。

更多工具的架构和实现原理详情，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/blob/master/docs/INSTRUCTION_ZH.md)

## 目录

	├── napi_generator                # NAPI框架代码生成工具
	│   ├── docs                      # 工具说明、版本规划
	│   ├── examples                  # 工具需要的文件样例 
	│   ├── figures                   # 图片资源文件
	│   ├── hdc                       # hdc相关工具
	│   ├── napi_IntelliJ_plugin      # Intellij IDEA插件代码
	│   ├── napi_vs_plugin            # VS Code插件代码
	│   ├── release-notes             # 发布说明
	│   ├── src                       # 工具源码
	│   │   ├── gen                   # napi工具源码                 
	│   │   |   ├── analyze           # 解析器
	│   │   |   |── extend            # 扩展模块，包括gn文件生成、linux环境适配代码等
	│   │   |   |── generate          # 生成器
	│   │   |   └── tools             # 公共模块代码，包括消息体校验、文件读写、正则表达式转换等
	│   │   ├── tsGen                 # TS工具源码
	│   ├── test                      # UT、ST测试
	│   ├── FAQ                       # NAPI框架工具问题反馈
	│   └── README                    # 工具使用指导     

## 约束
系统：建议Ubuntu 20.04或者Windows 10

依赖版本：VS Code 1.62.0

## 使用方法

### 使用对象

系统开发者

### 使用场景

1) 系统框架层新增子系统，需对应用层提供接口。
2) 系统框架层子系统能力增强后，需对应用层提供新接口。

### 工具使用

工具有三种类型，分别是可执行文件、VS Code插件、DevEco Studio上使用的IntelliJ插件。其中的可执行文件可根据工具使用者的开发环境选择，支持Windows，Linux和Mac。可执行文件下载路径如下(由于网络原因，可能会导致有的下载链接失效，因此提供了以下三个下载链接):

[可执行文件下载链接1](http://ftpkaihongdigi.i234.me:5000/sharing/yaRiKSjBI)

[可执行文件下载链接2](http://ftp.kaihong.com:5000/fsdownload/yaRiKSjBI/)

[可执行文件下载链接3](http://ftp.kaihongdigi.com:5000/fsdownload/yaRiKSjBI/)

访问密码：kaihong

压缩包解压密码：kaihong20231121

DevEco Studio上使用的IntelliJ插件下载路径如下:

[DevEco Studio上使用的IntelliJ插件下载链接](https://plugins.jetbrains.com/plugin/19593-napi-generator/versions)

具体的工具使用步骤，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/blob/master/docs/INSTRUCTION_ZH.md)

### 工具输出

根据使用者指定的typescript文件，工具会输出NAPI框架代码、业务代码框架、GN脚本等文件。

为了方便使用者快速上手工具，可供测试的typescript文件存放在以下路径：

```
napi_generator/examples/ts
```

在window环境下的，根据输入文件@ohos.napitest.d.ts和basic.d.ts生成的输出文件，如下所示：

![](./figures/pic-d-ts-transition.png)

其中生成的"napitest.h"文件，定义了框架代码的接口，生成的部分接口如下所示：

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

### 代码集成

为了实现工具生成的接口被其他子系统或者应用调用，需将生成的代码编译集成到OpenHarmony系统中，编译生成动态库。

把工具的生成代码集成到OpenHarmony的具体操作步骤，可以左键单击以下链接了解：

[生成代码集成到OpenHarmony的方法](https://gitee.com/openharmony/napi_generator/blob/master/docs/ENSEMBLE_METHOD_ZH.md)

## 工具开发说明

### 对象

工具的开发者

### 开发场景

若当前工具的功能已经不能满足开发者的全部需求，则开发者可以基于已有的源码对工具进行二次开发，来增强工具的能力，编译打包生成自定义的可执行文件和插件。

### 开发步骤

开发者可以根据如下的步骤来完成对工具的开发：

 [工具开发说明](https://gitee.com/openharmony/napi_generator/blob/master/docs/DEVELOP_ZH.md)

## 版本说明

 当前版本已支持的特性和待开发的特性，如下所示：

 [已支持特性](https://gitee.com/openharmony/napi_generator/blob/master/release-notes)

 [待支持特性](https://gitee.com/openharmony/napi_generator/blob/master/docs/ROADMAP_ZH.md)

## FAQ
对于常见问题解决方法指导如下：

  [FAQ](https://gitee.com/openharmony/napi_generator/blob/master/FAQ.md)

## 参与贡献

暂无

## 相关仓

[ts生成工具README_zh](https://gitee.com/openharmony/napi_generator/blob/master/docs/ts/README_ZH.md)