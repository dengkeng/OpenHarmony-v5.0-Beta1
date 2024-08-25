# ASSIST工具IntelliJ插件说明

## 简介

ASSIST统一入口工具，可以将各北向工具统一起来，用户只需下载统一入口工具，在统一入口工具中按需下载北向工具，实现对工具链的使用。目前工具支持IntelliJ插件一种入口，本文主要介绍IntelliJ插件使用说明。

## 目录 


```
├── assist                     
│   ├── ...                           # 其它文件  
│   ├── assist_tools_IntelliJ_plugin  # IntelliJ插件代码
│   │   ├── docs                      # IntelliJ插件说明
│   │   ├── resources                 # IntelliJ插件说明
│   │   ├── src                       # IntelliJ插件源码
│   │   └── README_zh                 # IntelliJ插件说明
```

## 约束 

系统：建议Windows 10

依赖版本：JDK 11

开发工具：DevEco stdio、IDEA Community 2021.3.3

## 使用方法 

### 工具使用

插件下载路径如下，点击download下载。

[下载链接](https://plugins.jetbrains.com/plugin/21430-assist-tools/edit/versions)

具体的工具使用步骤，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/assist/assist_tools_IntelliJ_plugin/docs/INSTRUCTION_ZH.md)

## 开发说明

### 对象

工具的开发者

### 开发场景

若当前工具的功能已经不能满足开发者的全部需求，则开发者可以基于已有的源码对工具进行二次开发，来增强工具的能力，编译打包生成自定义的可执行文件和插件。
       
### 开发步骤

开发者可以根据如下的步骤来完成对工具IntelliJ插件的开发：

 [工具开发说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/assist/assist_tools_IntelliJ_plugin/docs/DEVELOP_ZH.md)
    

## 相关仓

暂无