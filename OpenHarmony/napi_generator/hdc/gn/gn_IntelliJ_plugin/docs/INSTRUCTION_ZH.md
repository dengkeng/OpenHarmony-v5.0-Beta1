# GN脚本转换工具IntelliJ插件使用说明

## 简介

IntelliJ插件下载路径如下：

[下载链接](暂无)               

## IntelliJ插件使用方法

### 依赖

系统：不限

开发工具：DevEco stdio

### 使用指导

1、windows中下载OpenHarmony源码，并编译成功一个产品的镜像包，此处以RK3568A为例。

2、将待三方库项目放置在third_party文件夹下，如下所示：

	E:\OpenHarmony\third_party\test_project>dir /B
	CMakeLists.txt
	main.c

3、DevEco stdio新建或打开项目工程，以下以新建项目工程为例。

File->New->Create Project。

![](../../figures/DevEco_step_newFile.png)

Ability Template选择Empty Ability,单击Next。

![](../../figures/DevEco_step_firstNext.png)

填写Project name、Save location,其他选项可不修改，单击Finish,新的工程就创建好了。

![](../../figures/DevEco_step_finish.png)

4、安装插件，File->Settings->Plugins->Installed->Install Plugin from Disk...，选择下载的gn_IntelliJ_plugin.jar，安装成功之后重启IDE。

![](../../figures/DevEco_step_pluginsOk.png)

![](../../figures/DevEco_step_applyPlugins.png)

5、Tools->Gn Generate Frame,打开Gn Generate Frame选择框。

![](../../figures/DevEco_step_gn.png)

6、Gn Generate Frame窗口中工具输出路径选择E:\OpenHarmony\out\rk3568-khdvk后，工程源码路径、输入脚本路径均自动填写为E:\OpenHarmony；输入脚本路径修改为三方库项目CMakeLists.txt的路径后，GN生成路径自动填写为CMakeLists.txt文件所在路径，使用者可根据实际情况修改路径；输入脚本类型默认为cmake，此处不做修改；子系统名称、组件名称使用者可根据具体情况修改；编译选项根据具体三方库项目选填。以上参数填写完成后，点击ok。

![](../../figures/DevEco_step_gn_ok.png)

7、执行结束后会在E:\OpenHarmony\third_party\test_project目录下生成build_tep文件夹，文件夹下内容如下所示：

	E:\OpenHarmony\third_party\test_project\build_tmp>dir /B
	BUILD.gn
	CMakeCache.txt
	CMakeFiles
	cmake_install.cmake
	hello
	Makefile
	ohos.toolchain.cmake


