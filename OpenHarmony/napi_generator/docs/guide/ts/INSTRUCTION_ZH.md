# Ts接口生成工具使用说明
## 简介

Ts接口生成工具支持两种入口，分别是可执行程序、IntelliJ插件，使用者可以根据自己的需要选择合适的工具。可执行文件、IntelliJ插件下载路径如下。

[下载链接1](http://ftpkaihongdigi.i234.me:5000/sharing/kBG1c7CvT)

[下载链接2](http://ftp.kaihong.com:5000/sharing/kBG1c7CvT)

[下载链接3](http://ftp.kaihongdigi.com:5000/sharing/kBG1c7CvT)

下载文件说明如下：

	│   │   |── generator.jar                   # IntelliJ插件
	│   │   |── header_parser       
	│   │   |── |── linux
	│   │   |── |── |── header_parser           # Linux下python脚本可执行程序
	│   │   |── |── windows
	│   │   |── |── |── header_parser.exe       # Windows下python脚本可执行程序
	│   │   |── |── src_code
	│   │   |── |── |── CppHeaderParser.zip     # CppHeaderParser源码
	│   │   |── |── readme.txt                  # readme.txt
	│   │   |── napi_generator-linux            # Linux可执行程序 
	│   │   |── napi_generator-win.exe          # Windows可执行程序    
	│   │   └── napi_generator-macos            # Mac可执行程序                

## 工具介绍

通过Ts接口生成工具，使用者可以将已有的.h接口文件生成ts文件，进而将生成的ts文件作为NAPI框架生成代码工具的输入，生成NAPI框架代码,达到工具链的效果。工具的软件架构如下:

![](../../../figures/ts_framework.png)


## 使用方法

### 可执行程序使用方法

#### Linux

1.将待转换的.h文件、napi_generator-linux、header_parser放在同级目录下,此处新建out文件夹，用于存放生成.d.ts文件。整体目录文件如下：

	harmony@Ubuntu-64:~/service/linshi$ ls
	baseapi.h  header_parser  napi_generator-linux  out

2.在终端中进入到之前可执行程序napi_generator-linux所在的目录，并运行napi_generator-linux，命令如下：

	harmony@Ubuntu-64:~/service/linshi$ ./napi_generator-linux -f baseapi.h -t true -o out

其中，参数详情如下：
  -f, 待转换的.h文件，若同时转换多个文件，文件之间用“,”隔开；
  -d, 根据指定路径转换该文件夹中所有.h文件；
  -t, 区分ts生成与napi转换工具，值为true时表示ts生成，false表示napi转换，默认为false；
  -o, 可选参数，默认为当前目录，指定生成框架代码输出路径。

  备注：-f与-d两个参数只选其中一个参数即可。

3.运行成功后会在out目录下生成.d.ts文件，如下所示：

	harmony@Ubuntu-64:~/linshi/napi_generator_8/examples/ts/out$ ls
	napi_gen.log  baseapi.d.ts

#### Windows

1.将待转换的.h文件、napi_generator-win.exe、header_parser.exe放在同级目录下,此处新建out文件夹，用于存放生成.d.ts文件。整体目录文件如下：

	E:\demo\napi>dir /B
	baseapi.h
	header_parser.exe
	napi_generator-win.exe
	out

2.在终端中进入到之前可执行程序napi_generator-win.exe所在的目录，并运行napi_generator-win.exe，命令如下：

	E:\demo\napi>napi_generator-win.exe -f baseapi.h -t true -o out

其中，参数详情如下：
  -f, 待转换的.h文件，若同时转换多个文件，文件之间用“,”隔开；
  -d, 根据指定路径转换该文件夹中所有.h文件；
  -t, 区分ts生成与napi转换工具，值为true时表示ts生成，false表示napi转换，默认为false；
  -o, 可选参数，默认为当前目录，指定生成框架代码输出路径。

  备注：-f与-d两个参数只选其中一个参数即可。

3.运行成功后会在out目录下生成.d.ts文件，如下所示：

	E:\demo\napi\out>dir /B
	napi_gen.log
	baseapi.d.ts

#### Mac

方法步骤参考windows、Linux的使用方法。

### IntelliJ插件使用方法

具体的插件使用步骤，可以左键单击以下链接了解：

[IntelliJ插件使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/ts/ts_IntelliJ_plugin/docs/INSTRUCTION_ZH.md)
