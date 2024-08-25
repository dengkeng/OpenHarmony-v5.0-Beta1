# 手动配置业务代码后集成到OpenHarmony的方法

## 场景说明

为了实现工具生成的接口被其它子系统或者应用调用，需将生成的代码编译集成到OpenHarmony系统中，使其生成动态库，供OpenHarmony应用层调用。
本文介绍如何手动配置业务代码并将生成的代码集成到OpenHarmony 4.0 Release。

## 4.0 版本

### 建立模块位置

模块目录理论上可在OpenHarmony工程的任一位置，假设OpenHarmony代码库的目录为OHOS_SRC，在OHOS_SRC/foundation目录下，建测试模块目录：napitest。napitest目录结构如下：

    napitest
    |-- binding.gyp
    |-- BUILD.gn
    |-- bundle.json
    |-- napitest.cpp
    |-- napitest.h
    |-- napitest_middle.h
    |-- napitest_middle.cpp
    |-- test.sh
    |-- tool_utility.cpp
    |-- tool_utility.h

其中bundle.json为新增的编译配置文件，其它为工具生成的代码。

### 编译修改点

#### 修改bundle.json文件

其中destPath选项中的"//foundation/napitest"指的是napitest目录，":napitest"指的是上面BUILD.gn中的目标ohos_shared_library("napitest")。

```
{
  "name": "@ohos/napitest",
  "description": "napitest provides atomic capabilities",
  "version": "4.0",
  "license": "Apache License 2.0",
  "publishAs": "code-segment",
  "segment": {
    "destPath": "foundation/napitest"
  },
  "dirs": {},
  "scripts": {},
  "component": {
    "name": "napitest",
    "subsystem": "napitest",
    "features": [],
    "adapted_system_type": [
      "standard"
    ],
    "rom": "10000KB",
    "ram": "10000KB",
    "deps": {
      "components": [
        "ace_napi",
        "ipc_core",
        "libhilog"
      ],
      "third_party": [
        "node"
      ]
    },
    "build": {
      "sub_component": [
        "//foundation/napitest:napitest"
      ],
      "inner_kits": [
        {
          "header": {
            "header_base": "//foundation/napitest",
            "header_files": [
              "tool_utility.h",
              "napitest.h",
              "napitest_middle.h"
            ]
          },
          "name": "//foundation/napitest:napitest"
        }
      ]
    }
  }
}
```

#### 修改napitest.cpp文件

为方便调试，在napitest.cpp文件中增加业务代码。以修改napitest.cpp文件为例，在以下方法中增加业务代码，

在sayHello方法中增加注册的object回调方法的调用：

```
...
// 业务代码调用 onSayHelloStart callback
napitest::napitest_interface::NodeISayHello::listener_.NodeISayHelloListener_onSayHelloStartCallback(info1);
// 业务代码调用 onSayHelloEnd callback
napitest::napitest_interface::NodeISayHello::listener_.NodeISayHelloListener_onSayHelloEndCallback(info2);
...
```

在sayHi方法中增加register注册的回调方法的调用：

```
...
napitest::napitest_interface::NodeISayHello *ptr = new napitest::napitest_interface::NodeISayHello();
uint32_t callbackNum = 50;
ptr->CallbackfuncCallback(callbackNum);
delete ptr;
...
```

在sayHelloWithResponse方法中增加Promise回调方法的调用：

```
...
out.errMsg = "";
out.response = "rec hello.";
out.result = 0;
...
```

在funcTest方法中增加普通函数的业务逻辑：

```
...
if (v) {
    out = "ret is true";
} else {
    out = "ret is false";
}
...
```

增加业务代码之后的文件如下所示：

[napitest.cpp](https://gitee.com/openharmony/napi_generator/blob/master/examples/napitest.cpp)

#### 增加子系统

在源码/build/subsystem_config.json中增加子系统选项。如下所示：

```
"napitest": {
    "path": "foundation/napitest",
    "name": "napitest"
  }
```

### 添加功能模块

在产品配置中添加上述子系统的功能模块，编译到产品产出文件中，例如在源码vendor/hihope/rk3568/config.json中增加part选项，其中第一个napitest就是BUILD.gn文件中的subsystem_name，第二个napitest就是BUILD.gn文件中的part_name。

```
{
      "subsystem": "napitest",
      "components": [
        {
          "component": "napitest",
          "features": []
        }
      ]
}
```

### 编译验证

编译成功后，就会在 /out/产品名/packages/phone/system/lib/module/ 生成libnapitest.z.so，如下所示：

    /out/rk3568/packages/phone/system/lib/module

