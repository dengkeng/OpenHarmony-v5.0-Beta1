# 手动配置业务代码说明
## 简介

工具生成框架代码时支持使用cfg.json文件配置业务代码，当用户自动配置业务代码无法达成目的时也可手动进行业务代码配置，本文主要介绍不使用配置文件cfg.json进行业务代码配置并生成框架代码的过程。

## 生成框架

### 可执行程序使用方法

#### Linux

1.将待转换的.d.ts文件、依赖文件basic.d.ts、napi_generator-linux放在同级目录下。此处新建generatorCode文件夹，用于存放生成框架代码。整体目录文件如下：

	OpenHarmony@Ubuntu-64:~/service$ ls
	napi_generator-linux  @ohos.napitest.d.ts  basic.d.ts  generatorCode

2.在终端中进入到之前可执行程序napi_generator-linux所在的目录，并运行napi_generator-linux，命令如下：

	OpenHarmony@Ubuntu-64:~/service$ ./napi_generator-linux -f @ohos.napitest.d.ts -o generatorCode -i false -n int

其中，参数详情如下：

   -f, 待转换的.d.ts文件，若同时转换多个文件，文件之间用“,”隔开；

  -d, 根据指定路径转换该文件夹中所有.d.ts文件；

  -i, 可选参数，默认false，待转换.d.ts文件中引用非basic.d.ts的ts文件时打开开关；

  -o, 可选参数，默认为当前目录，指定生成框架代码输出路径；

  -n, 可选参数，默认为uint32_t，指定生成框架代码中number类型全部为指定类型；

  -s, 可选参数，默认为不配置业务代码，指定生成框架代码的业务配置文件，用于粘合工具代码和业务代码的配置。

  备注1：-f与-d两个参数只选其中一个参数即可。

  备注2：若.d.ts文件中声明了basic.d.ts文件，将basic.d.ts文件放置在待转换.d.ts文件同一级目录；若除此之外还声明其它.d.ts文件，将此类文件放置在待转换.d.ts文件同级目录。

3.运行成功后会在generatorCode目录下生成框架代码文件，如下所示：

	OpenHarmony@Ubuntu-64:~/linshi/napi_generator_8/examples/ts/generatorCode$ ls
	binding.gyp  BUILD.gn  napi_gen.log  napitest.cpp  napitest.h  napitest_middle.h  napitest_middle.cpp  test.sh  tool_utility.cpp  tool_utility.h

#### Windows

1.将待转换的.d.ts文件、依赖文件basic.d.ts、napi_generator-win.exe放在同级目录下。此处新建generatorCode文件夹，用于存放生成框架代码。整体目录文件如下：

	E:\demo\napi>dir /B
	@ohos.napitest.d.ts
	basic.d.ts
	napi_generator-win.exe
	generatorCode

2.在终端中进入到之前可执行程序napi_generator-win.exe所在的目录，并运行napi_generator-win.exe，命令如下：

	E:\demo\napi>napi_generator-win.exe -f @ohos.napitest.d.ts -o generatorCode -i false -n double

其中，参数详情如下：

   -f, 待转换的.d.ts文件，若同时转换多个文件，文件之间用“,”隔开；

  -d, 根据指定路径转换该文件夹中所有.d.ts文件；

  -i, 可选参数，默认false，待转换.d.ts文件中引用非basic.d.ts的ts文件时打开开关；

  -o, 可选参数，默认为当前目录，指定生成框架代码输出路径；

  -n, 可选参数，默认为uint32_t，指定生成框架代码中number类型全部为指定类型；

  -s, 可选参数，默认为不配置业务代码，指定生成框架代码的业务配置文件，用于粘合工具代码和业务代码的配置。

  备注1：-f与-d两个参数只选其中一个参数即可。

  备注2：若.d.ts文件中声明了basic.d.ts文件，将basic.d.ts文件放置在待转换.d.ts文件同一级目录；若除此之外还声明其它.d.ts文件，将此类文件放置在待转换.d.ts文件同级目录。

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

### VS Code插件使用方法

具体的插件使用步骤，可以左键单击以下链接了解：

[VS插件使用说明](https://gitee.com/openharmony/napi_generator/blob/master/napi_vs_plugin/docs/napi/INSTRUCTION_ZH.md)

### DevEco Studio上使用的IntelliJ插件使用方法

具体的插件使用步骤，可以左键单击以下链接了解：

[DevEco Studio上使用的IntelliJ插件使用说明](https://gitee.com/openharmony/napi_generator/blob/master/napi_IntelliJ_plugin/docs/napi/INSTRUCTION_ZH.md)

## 集成测试
NAPI框架代码生成后，系统框架开发者进行二次开发后，即可集成到OpenHarmony编译系统，生成对应的库文件，供应用开发者调用接口。工具集成测试的具体操作步骤可以左键单击以下链接了解：

  [工具集成测试](https://gitee.com/openharmony/napi_generator/blob/master/docs/guide/INTEGRATION_TESTING_ZH.md)

