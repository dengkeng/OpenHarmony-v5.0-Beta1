# GN脚本转换工具开发说明

若当前工具功能不满足开发者需求，开发者需增强工具能力，则可基于已有源码进行工具二次开发，编译打包生成自定义的可执行文件和插件。

## 工具开发

### 可执行文件开发说明

#### 环境说明

系统：建议Ubuntu 20.04或者Windows 10

#### 开发步骤

##### Linux

1.下载res文件夹，并放置到napi_generator/hdc/gn/gn-gen目录下，下载链接如下：

[下载链接](http://ftpkaihongdigi.i234.me:5000/fsdownload/1OjtRhtGf/gn-gen-0.0.1)

2.安装typescript：在napi_generator/hdc/gn/gn-gen/src目录下执行命令：

	npm i typescript

3.安装stdio：在napi_generator/hdc/gn/gn-gen目录下执行命令：

	npm i stdio

4.安装pkg : 在napi_generator/hdc/gn/gn-gen目录下执行命令：

	sudo npm i -g pkg

5.打包三个版本 : 执行命令：

	pkg .

执行以上步骤后，即可在napi_generator/hdc/gn/gn-gen目录下生成Windows、linux、mac系统下的可执行程序:

	gn-gen-win.exe、gn-gen-linux、gn-gen-macos

6.根据需求打包指定系统下的可执行文件。若想只打包windows系统下可执行文件，可执行命令：

	pkg -t node14-win . -o gn-gen-win.exe

若想只打包linux系统下可执行文件，可执行命令：

	pkg -t node14-linux . -o gn-gen-linux

若想只打包macos系统下可执行文件，可执行命令：

	pkg -t node14-macos . -o gn-gen-macos

备注：参数-t为指定系统，参数-o为指定可执行文件名称。


##### Windows

1.下载res文件夹，并放置到napi_generator/hdc/gn/gn-gen目录下，下载链接如下：

[下载链接](http://ftpkaihongdigi.i234.me:5000/fsdownload/1OjtRhtGf/gn-gen-0.0.1)

2.安装typescript：使用管理员身份在napi_generator/hdc/gn/gn-gen/src目录下执行命令：

	npm i typescript

3.安装stdio：使用管理员身份在napi_generator/hdc/gn/gn-gen目录下执行命令：

	npm i stdio

4.安装pkg : 使用管理员身份在napi_generator/hdc/gn/gn-gen目录下执行命令：

	npm i -g pkg

5.打包三个版本 : 使用管理员身份执行命令：

	pkg .

执行以上步骤后，即可在napi_generator/hdc/gn/gn-gen目录下生成Windows、linux、mac系统下的可执行程序:

	gn-gen-win.exe、gn-gen-linux、gn-gen-macos

6.根据需求打包指定系统下的可执行文件。若想只打包windows系统下可执行文件，可执行命令：

	pkg -t node14-win . -o gn-gen-win.exe

若想只打包linux系统下可执行文件，可执行命令：

	pkg -t node14-linux . -o gn-gen-linux

若想只打包macos系统下可执行文件，可执行命令：

	pkg -t node14-macos . -o gn-gen-macos

### VS插件开发说明

具体的插件开发步骤，可以左键单击以下链接了解：

[VS插件开发说明](https://gitee.com/openharmony/napi_generator/blob/master/hdc/gn/gn_vs_plugin/docs/DEVELOP_ZH.md)

