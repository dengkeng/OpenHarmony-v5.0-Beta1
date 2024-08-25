# Ts接口生成工具IntelliJ插件使用说明

## 简介

Ts接口生成工具目前支持两种入口，分别是可执行程序、IntelliJ插件，本文主要介绍IntelliJ插件使用说明。IntelliJ插件下载路径如下，点击download下载。

[下载链接](https://plugins.jetbrains.com/plugin/21420-ts-generator/edit/versions)

## IntelliJ插件使用方法

### 依赖

系统：建议Windows 10

开发工具：DevEco Studio

### 使用指导

1.新建或打开项目工程，以下以新建项目工程为例。

File->New->Create Project。

![](../../figures/DevEco_step_newFile.png)

Ability Template选择Empty Ability,单击Next。

![](../../figures/DevEco_step_firstNext.png)

填写Project name、Save location,其它选项可不修改，单击Finish,新的工程就创建好了。

![](../../figures/DevEco_step_finish.png)

2.安装插件，File->Settings->Plugins->Installed->Install Plugin from Disk...，选择下载的generator.jar，安装成功之后重启IDE。

![](../../figures/DevEco_step_pluginsOk.png)

![](../../figures/DevEco_step_napiPlugins.png)

3.把需要转换的.h文件放在DevEco stdio新建项目的src目录下。

![](../../figures/DevEco_step_ts.png)

4.选择.h文件,点击右键选择Generate Ts Frame，工具弹出Generate Ts Frame弹窗,选择Ts-Gen页签。文件路径文本框填写.h文件路径；输出目录选择文本框填写生成.d.ts文件存放路径，点击ok。

![](../../figures/DevEco_step_tsGenerate.png)

![](../../figures/DevEco_step_ts_ok.png)

5.执行结束后会在输出目录下生成.d.ts代码文件。
