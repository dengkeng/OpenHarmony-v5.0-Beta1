# NAPI框架生成工具使用说明
## 简介

NAPI框架生成工具支持三种入口，分别是可执行程序、VS Code插件、DevEco Studio上使用的IntelliJ插件，使用者可以根据自己的需要选择合适的工具。

1.可执行文件下载路径如下(由于网络原因，可能会导致有的下载链接失效，因此提供了以下三个下载链接):

[可执行文件下载链接1](http://ftpkaihongdigi.i234.me:5000/sharing/yaRiKSjBI)

[可执行文件下载链接2](http://ftp.kaihong.com:5000/fsdownload/yaRiKSjBI/)

[可执行文件下载链接3](http://ftp.kaihongdigi.com:5000/fsdownload/yaRiKSjBI/)

访问密码：kaihong

压缩包解压密码：kaihong20231121

DevEco Studio上使用的IntelliJ插件下载路径如下：

[DevEco Studio上使用的IntelliJ插件下载链接](https://plugins.jetbrains.com/plugin/19593-napi-generator/versions)

## 工具介绍

通过NAPI框架生成工具，使用者可输入一个接口定义的ts文件，一键生成NAPI框架代码、业务代码框架、GN脚本等文件，并使用生成的NAPI接口及功能。使用者也可以输入一个定义方法的.h头文件，反向生成ts文件。

![](../../figures/pic-frm.png)

## 预检查

napi_generator的可执行程序方式和插件方式都具有预检查的功能，如果.d.ts文件中存在语法错误，那么执行的时候命令行会打印出错误信息，指出代码中存在错误的行号。使用效果如下：

	joey@joey-virtual-machine:~/code/napi_test$ ./napi_generator-linux -f @ohos.napitest.d.ts
	@ohos.napitest.d.ts (33,12): Identifier expected.
	@ohos.napitest.d.ts (33,13): ';' expected.
	@ohos.napitest.d.ts (33,13): An identifier or keyword cannot immediately follow a numeric literal.
	@ohos.napitest.d.ts (33,13): Cannot find name 'shutdownDevice'.
	@ohos.napitest.d.ts (33,28): Cannot find name 'reason'.
	@ohos.napitest.d.ts (33,34): ',' expected.
	@ohos.napitest.d.ts (33,36): 'string' only refers to a type, but is being used as a value here.
	@ohos.napitest.d.ts (33,43): ';' expected.
	@ohos.napitest.d.ts (33,49): Expression expected.
	
	joey@joey-virtual-machine:~/code/napi_test$ 

@ohos.napitest.d.ts (33,49)，其中括号中第一个参数含义为行号，第二个参数含义为列号。

预检查的触发方式与生成框架的入口一致，使用方法参见生成框架描述。

## 生成框架

### 自动配置业务代码用例

1.ts文件用例

 [@ohos.napitest.d.ts](https://gitee.com/openharmony/napi_generator/blob/master/examples/ts/@ohos.napitest.d.ts)

注册关键字说明

(1) registerXXX/unRegisterXXX

register与unRegister成对使用, registerXXX用于注册回调，其参数即为注册的回调函数，注册之后在其它普通方法中即可在C++层调用registerXXX注册的回调函数；unRegisterXXX用于注销回调，其参数即为需要注销的回调函数，注销之后将无法再在C++层调用注销的回调函数。如：

```
export class NodeISayHello
{ 
    ...
    // register注册回调
    registerCallbackfunc(cb : (wid: number) => string);
    // unRegister注销回调
    unRegisterCallbackfunc(cb : (wid: number) => string);
    ...
}
```

其中注册/注销的回调方法为箭头函数 (wid: number) => string。注册回调之后，工具会生成回调方法CallbackfuncCallback，业务代码中用户自行定义回调时机进而通过回调接口调用回调，若回调被注销，则业务代码无法触发该回调。

(2) addXXX/removeXXX   onXXX

addXXX与removeXXX成对使用，addXXX用于注册回调，其参数为class对象, 将需要注册的回调函数放于class中，其写法为onXXX，class中可以有多个onXXX回调函数；removeXXX用于注销回调，其参数为class对象，用于注销addXXX注册的回调。如：

```
export class NodeISayHello
{ 
    ...
    // 注册object回调
    addSayHelloListener(listener: NodeISayHelloListener);
    // 注销object回调
    removeSayHelloListener(listener: NodeISayHelloListener);
    ...
}
...
export class NodeISayHelloListener
{   // 定义回调
    onSayHelloStart(info: SayInfo);
    onSayHelloEnd(info: SayInfo);
}
```

其中注册/注销的回调方法为onSayHelloStart(info: SayInfo); onSayHelloEnd(info: SayInfo); 注册回调之后，工具会生成两个回调接口供用户调用，业务代码中用户自行定义回调时机进而通过回调接口调用回调，若回调被注销，则业务代码无法触发回调。

2.自动配置业务代码用例使用的cfg.json

 [配置文件cfg.json用例](https://gitee.com/openharmony/napi_generator/blob/master/examples/cfg.json)

3.自动配置业务代码使用的业务代码用例

业务代码用例如下：

serviceCode/NodeISayHello.h

[NodeISayHello.h](https://gitee.com/openharmony/napi_generator/blob/master/examples/serviceCode/NodeISayHello.h)

serviceCode/NodeISayHello.cpp

[NodeISayHello.cpp](https://gitee.com/openharmony/napi_generator/blob/master/examples/serviceCode/NodeISayHello.cpp)

### 可执行程序使用方法

#### Linux

1.将待转换的.d.ts文件、napi_generator-linux、依赖文件basic.d.ts、 配置文件cfg.json、业务代码文件夹serviceCode（其中serviceCode目录下放置业务代码的.h文件和.cpp文件）放在同级目录下。此处新建generatorCode文件夹，用于存放生成框架代码。整体目录文件如下：

	OpenHarmony@Ubuntu-64:~/service$ ls
	napi_generator-linux  @ohos.napitest.d.ts  basic.d.ts  generatorCode  cfg.json  serviceCode

2.在终端中进入到之前可执行程序napi_generator-linux所在的目录，并运行napi_generator-linux，命令如下：

	OpenHarmony@Ubuntu-64:~/service$ ./napi_generator-linux -f @ohos.napitest.d.ts -o generatorCode -i false -n int -s cfg.json

其中，参数详情如下：

   -f, 待转换的.d.ts文件，若同时转换多个文件，文件之间用“,”隔开；

  -d, 根据指定路径转换该文件夹中所有.d.ts文件；

  -i, 可选参数，默认false，待转换.d.ts文件中引用非basic.d.ts的ts文件时打开开关；

  -o, 可选参数，默认为当前目录，指定生成框架代码输出路径；

  -n, 可选参数，默认为uint32_t，指定生成框架代码中number类型全部为指定类型；

  -s, 可选参数，默认为不配置业务代码，指定生成框架代码的业务配置文件，用于粘合工具代码和业务代码的配置。

  备注1：-f与-d两个参数只选其中一个参数即可。

  备注2：若.d.ts文件中声明了basic.d.ts文件，将basic.d.ts文件放置在待转换.d.ts文件同一级目录；若除此之外还声明其它.d.ts文件，将此类文件放置在待转换.d.ts文件同级目录。

其中，cfg.json内容如下：

```
[
 {
  "genPath": "/home/kaihong1/napi/myCommitNapiTest/generatorCode",
  "includeName": "../serviceCode/NodeISayHello.h",
  "cppName": "../serviceCode/NodeISayHello.cpp",
  "interfaceName": "funcTest",
  "serviceCode": "out = napitest::funcTest(v);"
  "description": "includeName: 引入的业务代码.h文件相对路径, cppName: 引入的业务代码.cpp文件相对路径, interfaceName: ts文件中的使用接口名,业务代码就在该接口中调用;格式为：类名::方法名(如: TestClass::funcTest1)，若无类名，则格式为：方法名(如： funcTest), serviceCode: 在接口中调用业务代码的调用语句。（该属性只做注释使用）"
 }
]
```

cfg.json是一个数组，每一项配置对应一个方法的调用，需要对多少方法进行调用就配置多少项；其中

"genPath": 生成框架代码路径，用户的业务代码相对于该路径配置，如："/home/kaihong1/napi/myCommitNapiTest/generatorCode"

"includeName": 引入的业务代码.h文件相对路径, 如："../serviceCode/NodeISayHello.h",

"cppName": 引入的业务代码.cpp文件相对路径,  如："../serviceCode/NodeISayHello.cpp",

"interfaceName": ts文件中的使用接口名,业务代码就在该接口中调用;格式为：类名::方法名(如: TestClass::funcTest1)，若无类名，则格式为：方法名(如： funcTest), 

"serviceCode": 在接口中调用业务代码的调用语句。此处调用的是实现该接口的业务代码， 如："out = napitest::funcTest(v);",

"description": 仅作为cfg.json文件中描述其它字段含义的属性，用户配置时，可以不用填写这个字段

3.运行成功后会在generatorCode目录下生成框架代码文件，如下所示：

	OpenHarmony@Ubuntu-64:~/linshi/napi_generator_8/examples/ts/generatorCode$ ls
	binding.gyp  BUILD.gn  napi_gen.log  napitest.cpp  napitest.h  napitest_middle.h napitest_middle.cpp  test.sh  tool_utility.cpp  tool_utility.h

#### Windows

1.将待转换的.d.ts文件、napi_generator-win.exe、 配置文件cfg.json、依赖文件basic.d.ts、业务代码文件夹serviceCode（其中serviceCode目录下放置业务代码的.h文件和.cpp文件）放在同级目录下。此处新建generatorCode文件夹，用于存放生成框架代码。整体目录文件如下：

	E:\demo\napi>dir /B
	@ohos.napitest.d.ts
	basic.d.ts
	napi_generator-win.exe
	generatorCode
	cfg.json
	serviceCode

2.在终端中进入到之前可执行程序napi_generator-win.exe所在的目录，并运行napi_generator-win.exe，命令如下：

	E:\demo\napi>napi_generator-win.exe -f @ohos.napitest.d.ts -o generatorCode -i false -n double -s cfg.json

其中，参数详情如下：

   -f, 待转换的.d.ts文件，若同时转换多个文件，文件之间用“,”隔开；

  -d, 根据指定路径转换该文件夹中所有.d.ts文件；

  -i, 可选参数，默认false，待转换.d.ts文件中引用非basic.d.ts的ts文件时打开开关；

  -o, 可选参数，默认为当前目录，指定生成框架代码输出路径；

   -n, 可选参数，默认为uint32_t，指定生成框架代码中number类型全部为指定类型；

  -s, 可选参数，默认为不配置业务代码，指定生成框架代码的业务配置文件，用于粘合工具代码和业务代码的配置。

  备注1：-f与-d两个参数只选其中一个参数即可。

  备注2：若.d.ts文件中声明了basic.d.ts文件，将basic.d.ts文件放置在待转换.d.ts文件同一级目录；若除此之外还声明其它.d.ts文件，将此类文件放置在待转换.d.ts文件同级目录。

其中，cfg.json内容如下：

```
[
 {
  "genPath": "E:\\napi_aboutTest\\testcase_napi_intellijPlugin\\generatorCode",
  "includeName": "../serviceCode/NodeISayHello.h",
  "cppName": "../serviceCode/NodeISayHello.cpp",
  "interfaceName": "funcTest",
  "serviceCode": "out = napitest::funcTest(v);"
  "description": "includeName: 引入的业务代码.h文件相对路径, cppName: 引入的业务代码.cpp文件相对路径, interfaceName: ts文件中的使用接口名,业务代码就在该接口中调用;格式为：类名::方法名(如: TestClass::funcTest1)，若无类名，则格式为：方法名(如： funcTest), serviceCode: 在接口中调用业务代码的调用语句。（该属性只做注释使用）"
 }
]
```

cfg.json是一个数组，每一项配置对应一个方法的调用，需要对多少方法进行调用就配置多少项；其中

"genPath": 生成框架代码路径，用户的业务代码相对于该路径配置，如："E:\\napi_aboutTest\\testcase_napi_intellijPlugin\\generatorCode"

"includeName": 引入的业务代码.h文件相对路径, 如："../serviceCode/NodeISayHello.h",

"cppName": 引入的业务代码.cpp文件相对路径,  如："../serviceCode/NodeISayHello.cpp",

"interfaceName": ts文件中的使用接口名,业务代码就在该接口中调用;格式为：类名::方法名(如: TestClass::funcTest1)，若无类名，则格式为：方法名(如： funcTest), 

"serviceCode": 在接口中调用业务代码的调用语句。此处调用的是实现该接口的业务代码， 如："out = napitest::funcTest(v);",

"description": 仅作为cfg.json文件中描述其它字段含义的属性，用户配置时，可以不用填写这个字段

3.运行成功后会在generatorCode目录下生成框架代码文件，如下所示：

	E:\demo\napi\generatorCode>dir /B
	binding.gyp
	BUILD.gn
	napitest.cpp
	napitest.h
	napitest_middle.h
	napitest_middle.cpp
	napi_gen.log
	test.sh
	tool_utility.cpp
	tool_utility.h

#### Mac

方法步骤参考windows、Linux的使用方法。

### 不配置cfg.json文件生成框架代码

若用户想手动配置业务代码，可不配置cfg.json文件生成框架代码之后手动增加业务代码，不配置cfg.json文件生成框架代码说明如下：

[不配置cfg.json生成框架代码说明](https://gitee.com/openharmony/napi_generator/blob/master/docs/guide/ADD_SERVICECODE_INSTRUCTION.md)

### VS Code插件使用方法

具体的插件使用步骤，可以左键单击以下链接了解：

[VS插件使用说明](https://gitee.com/openharmony/napi_generator/blob/master/napi_vs_plugin/docs/napi/INSTRUCTION_ZH.md)

### DevEco Studio上使用的IntelliJ插件使用方法

具体的插件使用步骤，可以左键单击以下链接了解：

[DevEco Studio上使用的IntelliJ插件使用说明](https://gitee.com/openharmony/napi_generator/blob/master/napi_IntelliJ_plugin/docs/napi/INSTRUCTION_ZH.md)

## 集成测试
NAPI框架代码生成后，系统框架开发者进行二次开发后，即可集成到OpenHarmony编译系统，生成对应的库文件，供应用开发者调用接口。工具集成测试的具体操作步骤可以左键单击以下链接了解：

  [工具集成测试](https://gitee.com/openharmony/napi_generator/blob/master/docs/guide/INTEGRATION_TESTING_ZH.md)

