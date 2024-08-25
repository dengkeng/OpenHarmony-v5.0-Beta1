# API扫描工具使用说明
## 简介

API扫描工具支持三种入口，分别是可执行程序、VS Code插件、IntelliJ插件，使用者可以根据自己的需要选择合适的工具。可执行文件、IntelliJ插件、VS Code插件下载路径如下：

待增加链接

下载文件说明如下：

	│   │   |── api_scan_IntelliJ_plugin.jar       # IntelliJ插件
	│   │   |── ApiScan-0.0.1.vsix                 # VS Code插件
	│   │   |── Andr_N_Games_api.xlsx              # 风险接口
	│   │   |── search-linux                       # Linux可执行程序 
	│   │   |── search-win.exe                     # Windows可执行程序    
	│   │   └── search-macos                       # Mac可执行程序                

## 工具介绍

通过API扫描工具，开发者可以扫描输出三方库中存在，而OpenHarmony源码中不存在的风险接口，移植之前预知风险，降低移植难度，提高开发效率。

![](./../figures/pic-api-frm.png)

## 生成result文件

### 可执行程序使用方法

#### Linux
1、Ubuntu中存在将要扫描的三方库源码，如下所示：

	harmony@Ubuntu-64:~/service$ ls /home/harmony/linshi/
	opencv

2、将下载的search-linux可执行程序放置任意路径下，如下所示：

	harmony@Ubuntu-64:~/service$ ls
	search-linux

3、进入到search-linux可执行程序路径下，并执行可执行程序，执行命令如下：

	harmony@Ubuntu-64:~/service$ ./search-linux -d /home/harmony/linshi/opencv/ -o ./
	{
	  function: Set(70) {
	    'AndroidBitmap_getInfo',
	    ......
	    'ANativeWindow_release'
	  },
	  include: Set(3) { 'bitmap.h', 'input.h', 'log.h' }
	}
	output: result.xlsx
	harmony@Ubuntu-64:~/service/napi_generator_8/hdc/api/API-Scan/example$ 

其中,参数详情如下：
	-d, 被扫描项目的路径；
	-o, 可选参数，默认为当前路径下，输出结果存放路径。

4、运行成功后会在当前目录下生成result.xlsx文件，如下所示：

	harmony@Ubuntu-64:~/service$ ls
	result.xlsx  search-linux

#### Windows

1、E:\workspace\杂七杂八\service\目录下存在将要扫描的项目opencv。

2、将下载的search-win.exe可执行程序放置任意路径下，如下所示：

	E:\demo\api>dir /B
	search-win.exe

3、进入search-win.exe可执行程序路径下，并执行可执行程序，执行过程如下：

	E:\demo\api>search-win.exe -d E:\workspace\杂七杂八\service\opencv -o ./
	{
	  function: Set(70) {
	    'AndroidBitmap_getInfo',
	    ......
	    'ANativeWindow_release'
	  },
	  include: Set(3) { 'bitmap.h', 'input.h', 'log.h' }
	}
	output: result.xlsx

其中,参数详情如下：
	-d, 被扫描项目的路径
	-o, 可选参数，默认为当前路径下，输出结果存放路径。

4、运行成功后会在当前目录下生成result.xlsx文件，如下所示：

	E:\demo\api>dir /B
	result.xlsx
	search-win.exe

#### Mac

方法步骤参考windows、Linux的使用方法。

### VS Code插件使用方法

具体的插件使用步骤，可以左键单击以下链接了解：

[VS插件使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/api/api_scan_vs_plugin/docs/INSTRUCTION_ZH.md)

### IntelliJ插件使用方法

具体的插件使用步骤，可以左键单击以下链接了解：

[IntelliJ插件使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/api/api_scan_IntelliJ_plugin/docs/INSTRUCTION_ZH.md)

