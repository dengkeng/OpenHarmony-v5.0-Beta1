# API扫描工具VSCode插件开发说明

若当前工具功能不满足开发者需求，开发者需增强工具能力，则可基于已有源码进行工具二次开发，编译打包生成自定义的VS Code插件。

## VS Code插件打包说明

### Linux

1.下载search-linux可执行程序，并放置在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下，下载链接如下：

待增加链接

2.在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下执行命令：

	npm i

3.在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下执行命令：

	npm i typescript

4.在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下执行命令：

	npm i vsce

5.在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下执行命令：

	npx vsce package

  每个选项都选择y，然后回车，最终会在当前目录下打包生成一个插件ApiScan-0.0.1.vsix。结果如下：

	kaihong1@ubuntu:~/napi_generator_gjj/hdc/api/api_scan_vs_plugin/src$ npx vsce package
	WARNING  A 'repository' field is missing from the 'package.json' manifest file.
	Do you want to continue? [y/N] y
	WARNING  Using '*' activation is usually a bad idea as it impacts performance.
	More info: https://code.visualstudio.com/api/references/activation-events#Start-up
	Do you want to continue? [y/N] y
	WARNING  LICENSE.md, LICENSE.txt or LICENSE not found
	Do you want to continue? [y/N] y
	This extension consists of 3282 files, out of which 1547 are JavaScript files. For performance reasons, you shoude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	DONE  Packaged: /home/kaihong1/napi_generator_gjj/hdc/api/api_scan_vs_plugin/src/ApiScan-0.0.1.vsix (3282 files, 50.34MB)


### Windows

1.下载search-win.exe可执行程序，并放置在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下，下载链接如下：

待增加链接

2.在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下执行命令：

	npm i

3.在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下执行命令：

	npm i typescript

4.在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下执行命令：

	npm i vsce

5.在napi_generator/hdc/api/api_scan_vs_plugin/src/目录下执行命令：

	npx vsce package

  每个选项都选择y，然后回车，最终会在当前目录下打包生成一个插件ApiScan-0.0.1.vsix。结果如下：

	C:\napi_generator_GJJ\hdc\api\api_scan_vs_plugin\src>npx vsce package
	WARNING  A 'repository' field is missing from the 'package.json' manifest file.
	Do you want to continue? [y/N] y
	WARNING  Using '*' activation is usually a bad idea as it impacts performance.
	More info: https://code.visualstudio.com/api/references/activation-events#Start-up
	Do you want to continue? [y/N] y
	WARNING  LICENSE.md, LICENSE.txt or LICENSE not found
	Do you want to continue? [y/N] y
	This extension consists of 3282 files, out of which 1547 are JavaScript files. For performance reasons, you should bundle your extension: https://aka.ms/vscode-bundle-extension . You should also exclude unnecessary files by adding them to your .vscodeignore: https://aka.ms/vscode-vscodeignore
	DONE  Packaged: C:\napi_generator_GJJ\hdc\api\api_scan_vs_plugin\src\ApiScan-0.0.1.vsix (3282 files, 47.42MB)

