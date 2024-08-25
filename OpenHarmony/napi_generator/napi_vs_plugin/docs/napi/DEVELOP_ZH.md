# NAPI框架生成工具VSCode插件开发说明

## 简介

若当前工具功能不满足开发者需求，开发者需增强工具能力，则可基于已有源码进行工具二次开发，编译打包生成自定义的VS Code插件。首先需下载可执行文件，可执行文件下载路径如下(由于网络原因，可能会导致有的下载链接失效，因此提供了以下三个下载链接):

[可执行文件下载链接1](http://ftpkaihongdigi.i234.me:5000/sharing/yaRiKSjBI)

[可执行文件下载链接2](http://ftp.kaihong.com:5000/fsdownload/yaRiKSjBI/)

[可执行文件下载链接3](http://ftp.kaihongdigi.com:5000/fsdownload/yaRiKSjBI/)

访问密码：kaihong

压缩包解压密码：kaihong20231121

## VS Code插件打包说明

### Linux

1.在napi_generator目录下，将napi_generator-linux下可执行文件复制到napi_generator/napi_vs_plugin/src/目录下，执行命令如下：

	cp napi_generator-linux napi_vs_plugin/src/

2.在napi_generator/napi_vs_plugin/src目录下执行命令：

	npm i

3.在napi_generator/napi_vs_plugin/src目录下执行命令：

	npm i typescript

4.在napi_generator/napi_vs_plugin/src目录下执行命令：

	npm i vsce

5.在napi_generator/napi_vs_plugin/src目录下执行命令：

	npx vsce package

  每个选项都选择y，然后回车，之后会在当前目录下打包生成一个插件gnapi-0.0.1.vsix。结果如下：

	harmony@Ubuntu-64:~/napi/napi_generator_5/napi_vs_plugin/src$ npx vsce package
	This extension consists of 3370 files, out of which 1627 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension . You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	DONE  Packaged: /home/harmony/napi/napi_generator_5/napi_vs_plugin/src/gnapi-0.0.1.vsix (3370 files, 44.42MB)

### Windows

1.将napi_generator目录下的napi_generator-win.exe可执行文件复制到napi_generator/napi_vs_plugin/src/目录下。

2.在napi_generator/napi_vs_plugin/src目录下执行命令：

	npm i

3.在napi_generator/napi_vs_plugin/src目录下执行命令：

	npm i typescript

4.在napi_generator/napi_vs_plugin/src目录下执行命令：

	npm i vsce

5.在napi_generator/napi_vs_plugin/src目录下执行命令：

	npx vsce package

  每个选项都选择y，然后回车，之后会在当前目录下打包生成一个插件gnapi-0.0.1.vsix。结果如下：

	E:\napi_generator\napi_generator-master\napi_vs_plugin\src>npx vsce package
	This extension consists of 3467 files, out of which 1692 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension . You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	DONE  Packaged: E:\napi_generator\napi_generator-master\napi_vs_plugin\src\gnapi-0.0.1.vsix (3467 files, 42.3MB)

## 工具测试

  进行工具二次开发后，本地可进行单元测试、story特性测试确保工具的可用性。左键单击以下链接了解详情：

  [单元测试](https://gitee.com/openharmony/napi_generator/blob/master/test/unittest/README_ZH.md)

  [story测试](https://gitee.com/openharmony/napi_generator/blob/master/test/storytest/README_ZH.md)

