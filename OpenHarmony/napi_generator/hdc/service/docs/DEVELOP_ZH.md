# SERVICE框架生成工具开发说明

若当前工具功能不满足开发者需求，开发者需增强工具能力，则可基于已有源码进行工具二次开发，编译打包生成自定义的可执行文件和插件。

## 工具开发

### 可执行文件开发说明

#### 环境说明

系统：建议Ubuntu 20.04或者Windows 10

#### 开发步骤

##### Linux

1.安装typescript：在napi_generator/hdc/service/service-gen/src目录下执行命令：

	npm i typescript

2.安装stdio：在napi_generator/hdc/service/service-gen目录下执行命令：

	npm i stdio

3.安装pkg : 在napi_generator/hdc/service/service-gen目录下执行命令：

	sudo npm i -g pkg

4.打包三个版本 : 执行命令：

	pkg .

执行以上步骤后，即可在napi_generator/hdc/service/service-gen目录下生成Windows、linux、mac系统下的可执行程序:

	service-gen-win.exe、service-gen-linux、service-gen-macos

5.根据需求打包指定系统下的可执行文件。若想只打包windows系统下可执行文件，可执行命令：

	pkg -t node14-win . -o service-gen-win.exe

若想只打包linux系统下可执行文件，可执行命令：

	pkg -t node14-linux . -o service-gen-linux

若想只打包macos系统下可执行文件，可执行命令：

	pkg -t node14-macos . -o service-gen-macos

备注：参数-t为指定系统，参数-o为指定可执行文件名称。

6.编译生成 header_parser.exe

6.1 安装python库 CppHeaderParser，在header_parser/src_code中下载CppHeaderParser.zip，解压后替换本地Python文件夹中CppHeaderParser(如 /usr/local/lib/python3.8/dist-packages/CppHeaderParser)目录下的全部文件(由于网络原因，可能会导致有的下载链接失效，因此提供了以下三个下载链接)

```
sudo pip install CppHeaderParser
```

[下载链接1](http://ftpkaihongdigi.i234.me:5000/sharing/kBG1c7CvT)

[下载链接2](http://ftp.kaihong.com:5000/sharing/kBG1c7CvT)

[下载链接3](http://ftp.kaihongdigi.com:5000/sharing/kBG1c7CvT)

6.2 安装pyinstaller

```
sudo pip install pyinstaller
```

6.3 将python脚本打包成独立可执行文件

进入 ./src/tsGen 目录后执行如下命令：

```
pyinstaller -F header_parser.py
```

打包后的可执行文件在dist目录中

```
./src/tsGen/dist/header_parser.exe
```


##### Windows

1.安装typescript：使用管理员身份在napi_generator/hdc/service/service-gen/src目录下执行命令：

	npm i typescript

2.安装stdio：使用管理员身份在napi_generator/hdc/service/service-gen目录下执行命令：

	npm i stdio

3.安装pkg : 使用管理员身份在napi_generator/hdc/service/service-gen目录下执行命令：

	npm i -g pkg

4.打包三个版本 : 使用管理员身份执行命令：

	pkg .

执行以上步骤后，即可在napi_generator/hdc/service/service-gen目录下生成Windows、linux、mac系统下的可执行程序:

	service-gen-win.exe、service-gen-linux、service-gen-macos

5.根据需求打包指定系统下的可执行文件。若想只打包windows系统下可执行文件，可执行命令：

	pkg -t node14-win . -o service-gen-win.exe

若想只打包linux系统下可执行文件，可执行命令：

	pkg -t node14-linux . -o service-gen-linux

若想只打包macos系统下可执行文件，可执行命令：

	pkg -t node14-macos . -o service-gen-macos

6.编译生成 header_parser.exe

6.1 安装python库 CppHeaderParser，在header_parser/src_code中下载CppHeaderParser.zip，解压后替换本地Python文件夹中CppHeaderParser(如 C:\Python310\Lib\site-packages\CppHeaderParser)目录下的全部文件(由于网络原因，可能会导致有的下载链接失效，因此提供了以下三个下载链接)

```
pip install CppHeaderParser
```

[下载链接1](http://ftpkaihongdigi.i234.me:5000/sharing/kBG1c7CvT)

[下载链接2](http://ftp.kaihong.com:5000/sharing/kBG1c7CvT)

[下载链接3](http://ftp.kaihongdigi.com:5000/sharing/kBG1c7CvT)

6.2 安装pyinstaller

```
pip install pyinstaller
```

6.3 将python脚本打包成独立可执行文件

进入 ./src/tsGen 目录后执行如下命令：

```
pyinstaller -F header_parser.py
```

打包后的可执行文件在dist目录中

```
./src/tsGen/dist/header_parser.exe
```
