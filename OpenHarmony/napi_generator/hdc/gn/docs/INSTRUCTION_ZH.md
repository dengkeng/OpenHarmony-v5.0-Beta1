# GN脚本转换工具可执行程序使用说明
## 简介

gn脚本生成工具目前支持两种入口，分别是可执行程序、VS Code插件，推荐使用VSCode插件。可执行文件、VS Code插件下载路径如下：

[下载链接](http://ftpkaihongdigi.i234.me:5000/fsdownload/1OjtRhtGf/gn-gen-0.0.1)

下载文件说明如下：

	│   │   |── res                           # 工具所需make文件
	│   │   |── gn-0.0.1.vsix                 # VS Code插件
	│   │   |── gn-gen-linux                  # Linux可执行程序 
	│   │   |── gn-gen-win.exe                # Windows可执行程序    
	│   │   └── gn-gen-macos                  # Mac可执行程序                

## 工具介绍

通过gn-gen生成工具，使用者可以基于OpenHarmony源码、已有编译脚本（目前支持cmake、make两种类型），生成OpenHarmony编译所需BUILD.gn脚本，实现将三方库移植到OpenHarmony上。gn-gen生成工具的软件架构如下：

![](./../figures/gn_framework.png)

## 可执行程序使用方法

### 环境说明

1、安装cmake，安装命令如下：

	sudo apt-get install cmake

### 生成ohos.toolchain.cmake

1、Ubuntu中下载OpenHarmony源码，并编译成功一个产品的镜像包，此处以RK3568为例。源码如下所示：

![](./../figures/pic-openharmony.png)

2、将待转换的三方库项目（路径：[三方库项目](https://gitee.com/openharmony/third_party_mbedtls)）放置在third_party文件夹下，如下所示：

![](./../figures/pic-mbedtls-development.png)

3、将下载的可执行程序gn-gen-linux与文件夹res放置在任意同一文件夹下。并将gn-gen-linux文件与res/linux/bin下文件赋可执行权限，如下所示：

	 harmony@Ubuntu-64:~/service/example$ ls
	 gn-gen-linux  res
	 harmony@Ubuntu-64:~/service/example$ sudo chmod -R 777 ./*
	 harmony@Ubuntu-64:~/service/example$ ll -A
	 总用量 116572
	 -rwxrwxrwx 1 harmony harmony 119361984 12月 15 09:41 gn-gen-linux*
	 drwxrwxrwx 5 harmony harmony      4096 12月 14 15:33 res/

4、在终端中进入到可执行程序gn-gen-linux所在的目录，并运行gn-gen-linux，命令如下：

	harmony@Ubuntu-64:~/service/example$ ./gn-gen-linux -o out/khdvk_rk3568_a -p /home/harmony/OpenHarmony -f third_party/mbedtls-development/CMakeLists.txt -t cmake -s test_subsystem -m mbedtls-development

![](./../figures/pic-generate-command.png)

其中,参数详情如下：

  -o：必填参数，ohos产品输出相对路径(例如：out/khdvk_rk3568_a)；

  -p：必填参数，ohos项目路径(例如：/home/harmony/OpenHarmony)；

  -f：必选参数，待转换三方库cmake文件相对路径(例如：third_party/mbedtls-development/CMakeLists.txt);

  -t：可选参数，默认为cmake;

  -s：可选参数，默认填写“test_subsystem”，使用者可根据实际情况修改子系统名称；

  -m：可选参数，工具默认填写“test_part”，使用者可根据实际情况修改组件名称；

  -d：可选参数，工具默认填写待转换三方库cmake文件所在文件夹相对路径，使用者可根据实际情况修改路径；

  -a：可选参数，待转换三方库中引用其它三方库时需填写该选项，具体填写方法可参考FAQ中libcoap转换时问题解决方法，详细FAQ内容可左键单击以下链接了解：[FAQ](https://gitee.com/openharmony/napi_generator/blob/master/hdc/gn/FAQ.md)；

5、运行完成后，进入/OpenHarmony/third_party/mbedtls-development/build_tmp目录下，查看是否存在ohos.toolchain.cmake文件，如下所示：

	 harmony@Ubuntu-64:~/service/example$ cd /home/harmony/OpenHarmony/third_party/mbedtls-development/build_tmp/
	 harmony@Ubuntu-64:~/OpenHarmony/third_party/mbedtls-development/build_tmp$ ll -A
	 总用量 228
	 drwxrwxr-x  3 harmony harmony   4096 12月 16 11:54 3rdparty/
	 -rw-rw-r--  1 harmony harmony  14658 12月 16 11:55 BUILD.gn
	 drwxrwxr-x  2 harmony harmony   4096 12月 16 11:54 cmake/
	 -rw-rw-r--  1 harmony harmony  17144 12月 16 11:54 CMakeCache.txt
	 drwxrwxr-x 10 harmony harmony   4096 12月 16 11:54 CMakeFiles/
	 -rw-rw-r--  1 harmony harmony   3879 12月 16 11:54 cmake_install.cmake
	 -rw-rw-r--  1 harmony harmony    432 12月 16 11:54 CTestTestfile.cmake
	 -rwxr--r--  1 harmony harmony    110 12月 16 11:54 DartConfiguration.tcl*
	 drwxrwxr-x  3 harmony harmony   4096 12月 16 11:54 include/
	 drwxrwxr-x  3 harmony harmony   4096 12月 16 11:55 library/
	 -rw-rw-r--  1 harmony harmony 122917 12月 16 11:54 Makefile
	 -rw-rw-r--  1 harmony harmony   1851 12月 16 11:54 ohos.toolchain.cmake
	 drwxrwxr-x 14 harmony harmony   4096 12月 16 11:54 programs/
	 lrwxrwxrwx  1 harmony harmony     65 12月 16 11:54 scripts -> /home/harmony/OpenHarmony/third_party/mbedtls-development/scripts/
	 drwxrwxr-x  4 harmony harmony  20480 12月 16 11:55 tests/

### 运行cmake脚本

1、在终端中进入ohos.toolchain.cmake所在的build_tmp目录下，运行cmake，查看cmake环境是否可以正常使用，命令如下：

	 harmony@Ubuntu-64:~/OpenHarmony/third_party/mbedtls-development/build_tmp$ cmake .. -DCMAKE_TOOLCHAIN_FILE=ohos.toolchain.cmake
	 -- The C compiler identification is Clang 10.0.1
	 -- Check for working C compiler: /home/harmony/OpenHarmony/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang
	 -- Check for working C compiler: /home/harmony/OpenHarmony/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang -- works
	 -- Detecting C compiler ABI info
	 -- Detecting C compiler ABI info - done
	 -- Detecting C compile features
	 -- Detecting C compile features - done
	 -- Configuring done
	 -- Generating done
	 -- Build files have been written to: /home/harmony/OpenHarmony/third_party/mbedtls-development/build_tmp

根据以上日志可发现cmake运行成功，环境正常使用。若运行cmake失败，则根据报错信息修改，直到cmake运行成功，环境正常使用为止。

### 生成gn脚本

1、在终端中进入到可执行程序gn-gen-linux所在的目录，并运行gn-gen-linux，命令如下：

	harmony@Ubuntu-64:~/service/example$ ./gn-gen-linux -o out/khdvk_rk3568_a -p /home/harmony/OpenHarmony -f  third_party/mbedtls-development/CMakeLists.txt -s test_subsystem -m mbedtls-development
	INFO (1) -- The C compiler identification is Clang 10.0.1
	
	INFO (2) -- Check for working C compiler: /home/harmony/OpenHarmony/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang
	
	INFO (3) -- Check for working C compiler: /home/harmony/OpenHarmony/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang -- works
	
	......
	
	INFO (647) -------------------generate gn ok

其中,参数详情如生成ohos.toolchain.cmake中步骤4。

2.运行成功后会在/OpenHarmony/third_party/mbedtls-development目录下生成build_tmp文件夹，build_tmp文件夹中包含BUILD.gn文件，如下所示：

![](./../figures/pic-build-tmp.png)

## VS Code插件使用方法

具体的插件使用步骤，可以左键单击以下链接了解：

[VS插件使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/gn/gn_vs_plugin/docs/INSTRUCTION_ZH.md)

## 将三方库集成到OpenHarmony的方法

具体的将三方库集成到OpenHarmony的步骤，可以左键单击以下链接了解：

[将三方库集成到OpenHarmony的方法](https://gitee.com/openharmony/napi_generator/tree/master/hdc/gn/docs/ENSEMBLE_METHOD_ZH.md)
