# SERVICE框架生成工具VSCode插件开发说明

若当前工具功能不满足开发者需求，开发者需增强工具能力，则可基于已有源码进行工具二次开发，编译打包生成自定义的VS Code插件。

## VS Code插件打包说明

### Linux

1.下载service-gen-linux可执行程序与header_parser可执行程序，并放置到到napi_generator/hdc/service/service_vs_plugin/src/目录下，下载链接如下：

待增加链接

2.在napi_generator/hdc/service/service_vs_plugin/src目录下执行命令：

	npm i

3.在napi_generator/hdc/service/service_vs_plugin/src目录下执行命令：

	npm i typescript

4.在napi_generator/hdc/service/service_vs_plugin/src目录下执行命令：

	npm i vsce

5.在napi_generator/hdc/service/service_vs_plugin/src目录下执行命令：

	npx vsce package

  每个选项都选择y，然后回车，最终会在当前目录下打包生成一个插件service-gen-0.0.1.vsix。结果如下：

	kaihong1@ubuntu:~/napi_generator_gjj/hdc/service/service_vs_plugin/src$ npx vsce package
	This extension consists of 3282 files, out of which 1547 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension . You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	DONE  Packaged: /home/kaihong1/napi_generator_gjj/hdc/service/service_vs_plugin/src/service-gen-0.0.1.vsix (3282 files, 60.4MB)

### Windows

1.下载service-gen-win.exe可执行程序与header_parser.exe可执行程序，并放置到到napi_generator/hdc/service/service_vs_plugin/src/目录下，下载链接如下：

待增加链接

2.在napi_generator/hdc/service/service_vs_plugin/src目录下执行命令：

	npm i

3.在napi_generator/hdc/service/service_vs_plugin/src目录下执行命令：

	npm i typescript

4.在napi_generator/hdc/service/service_vs_plugin/src目录下执行命令：

	npm i vsce

5.在napi_generator/hdc/service/service_vs_plugin/src目录下执行命令：

	npx vsce package

  每个选项都选择y，然后回车，最终会在当前目录下打包生成一个插件service-gen-0.0.1.vsix。结果如下：

	C:\napi_generator_GJJ\hdc\service\service_vs_plugin\src>npx vsce package
	This extension consists of 3281 files, out of which 1547 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension . You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	DONE  Packaged: C:\napi_generator_GJJ\hdc\service\service_vs_plugin\src\service-gen-0.0.1.vsix (3281 files, 39.92MB)

