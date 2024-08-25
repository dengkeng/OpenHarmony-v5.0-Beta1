# TS接口生成工具VSCode插件开发说明

若当前工具功能不满足开发者需求，开发者需增强工具能力，则可基于已有源码进行工具二次开发，编译打包生成自定义的VS Code插件。

## VS Code插件打包说明

### Linux

1.下载napi_generator-linux可执行程序与linux系统下header_parser.exe可执行程序，并放置在napi_generator/hdc/ts/ts_vs_plugin/src/目录下，下载链接如下(由于网络原因，可能会导致有的下载链接失效，因此提供了以下三个下载链接)：

[下载链接1](http://ftpkaihongdigi.i234.me:5000/sharing/kBG1c7CvT)

[下载链接2](http://ftp.kaihong.com:5000/sharing/kBG1c7CvT)

[下载链接3](http://ftp.kaihongdigi.com:5000/sharing/kBG1c7CvT)

2.在napi_generator/hdc/ts/ts_vs_plugin/src目录下执行命令：

	npm i

3.在napi_generator/hdc/ts/ts_vs_plugin/src目录下执行命令：

	npm i typescript

4.在napi_generator/hdc/ts/ts_vs_plugin/src目录下执行命令：

	npm i vsce

5.在napi_generator/hdc/ts/ts_vs_plugin/src目录下执行命令：

	npx vsce package

之后会在当前目录下打包生成一个插件ts-gen-0.0.1.vsix。结果如下：

	kaihong1@ubuntu:~/napi/napi_generator_test0419/napi_generator/hdc/ts/ts_vs_plugin/src$ npx vsce package
	This extension consists of 3212 files, out of which 1547 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension . You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	 DONE  Packaged: /home/kaihong1/napi/napi_generator_test0419/napi_generator/hdc/ts/ts_vs_plugin/src/ts-gen-0.0.1.vsix (3370 files, 44.42MB)

### Windows

1.下载napi_generator-win.exe可执行程序与Windows系统下header_parser.exe可执行程序，并放置在napi_generator/napi_vs_plugin/src/目录下，下载链接如下(由于网络原因，可能会导致有的下载链接失效，因此提供了以下三个下载链接)：

[下载链接1](http://ftpkaihongdigi.i234.me:5000/sharing/kBG1c7CvT)

[下载链接2](http://ftp.kaihong.com:5000/sharing/kBG1c7CvT)

[下载链接3](http://ftp.kaihongdigi.com:5000/sharing/kBG1c7CvT)

2.在napi_generator/hdc/ts/ts_vs_plugin/src目录下执行命令：

	npm i

3.在napi_generator/hdc/ts/ts_vs_plugin/src目录下执行命令：

	npm i typescript

4.在napi_generator/hdc/ts/ts_vs_plugin/src目录下执行命令：

	npm i vsce

5.在napi_generator/hdc/ts/ts_vs_plugin/src目录下执行命令：

	npx vsce package

  之后会在当前目录下打包生成一个插件ts-gen-0.0.1.vsix。结果如下：

	E:\napi_generator_aboutTest\zjx_gjj_napi230401\napi_generator\hdc\ts\ts_vs_plugin\src>npx vsce package
	This extension consists of 3218 files, out of which 1547 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension . You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	DONE  Packaged: E:\napi_generator_aboutTest\zjx_gjj_napi230401\napi_generator\hdc\ts\ts_vs_plugin\src\ts-gen-0.0.1.vsix (3467 files, 42.3MB)

