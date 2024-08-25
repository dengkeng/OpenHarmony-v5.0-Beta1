# ASSIST_TOOLS工具VS Code插件开发说明

若当前工具功能不满足开发者需求，开发者需增强工具能力，则可基于已有源码进行工具二次开发，编译打包生成自定义的VS Code插件。

## VS Code插件打包说明

### Linux

1.在napi_generator/hdc/assist/assist_tools_vs_plugin/src目录下执行命令：

	npm i

2.在napi_generator/hdc/assist/assist_tools_vs_plugin/src目录下执行命令：

	npm i typescript

3.在napi_generator/hdc/assist/assist_tools_vs_plugin/src目录下执行命令：

	npm i vsce

4.在napi_generator/hdc/assist/assist_tools_vs_plugin/src目录下执行命令：

	npx vsce package

之后会在当前目录下打包生成一个插件AssistTools-0.0.1.vsix。结果如下：

	kaihong1@ubuntu:~/napi/napi_generator_test0419/napi_generator/hdc/assist/assist_tools_vs_plugin/src$ npx vsce package
	This extension consists of 2166 files, out of which 1160 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension . You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	 DONE  Packaged: /home/kaihong1/napi/napi_generator_test0419/napi_generator/hdc/assist/assist_tools_vs_plugin/src/AssistTools-0.0.1.vsix (2166 files, 3MB)

### Windows

1.在napi_generator/hdc/assist/assist_tools_vs_plugin/src目录下执行命令：

	npm i

2.在napi_generator/hdc/assist/assist_tools_vs_plugin/src目录下执行命令：

	npm i typescript

3.在napi_generator/hdc/assist/assist_tools_vs_plugin/src目录下执行命令：

	npm i vsce

4.在napi_generator/hdc/assist/assist_tools_vs_plugin/src目录下执行命令：

	npx vsce package

  之后会在当前目录下打包生成一个插件AssistTools-0.0.1.vsix。结果如下：

	E:\napi_generator_aboutTest\zjx_gjj_napi230401\napi_generator\hdc\assist\assist_tools_vs_plugin\src>npx vsce package
	This extension consists of 2167 files, out of which 1160 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension . You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	 DONE  Packaged: E:\napi_generator_aboutTest\zjx_gjj_napi230401\napi_generator\hdc\assist\assist_tools_vs_plugin\src\AssistTools-0.0.1.vsix (2167 files, 3.18MB)

