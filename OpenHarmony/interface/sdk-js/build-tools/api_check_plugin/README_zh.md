#  Api_check工具

## 简介

该工具可用于校验 d.ts 声明文件中的JSDoc规范，并将不符合规范的JSDoc信息汇总成表格，提供给应用开发者

## 目录

```
├─config      #存放permission配置文件和JSDoc新增功能校验名单文件（标签值、标签顺序、标签使用合法性）
├─plugin      #存放词库
├─test        #本地运行使用文件，存放路径配置文件以及生成的表格
└─src         #存放源码
```

## 使用方法

### permission文件配置

在api_check_plugin/config文件夹下，存在名为“config.json”的文件，用于存放permission配置文件。打开链接中的仓库，打开systemres/main/config.json文件，将文件内容复制到api_check_plugin/config/config.json中（覆盖原内容）

[utils_system_resources: Providing system resources such as fonts | 字体等系统资源 (gitee.com)](https://gitee.com/openharmony/utils_system_resources)

### 填写待检查文件路径

打开api_check_plugin/test/mdFiles.txt文件，将待检查文件的路径填入此文件。

*注意：文件名与文件名之间直接换行，行尾无需加任何符号。*

### 安装

需要安装npm依赖环境

在interface_sdk-js/build-tools目录下执行：npm install;

在interface_sdk-js/build-tools/api_check_plugin目录下执行：npm install。

### 使用工具

在interface_sdk-js/build-tools/api_check_plugin同级目录下执行：npm run test。

