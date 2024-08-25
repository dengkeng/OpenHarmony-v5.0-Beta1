# NAPI框架生成工具单元测试

## 概述
为了验证代码与设计相符合，跟踪需求和设计的实现，发现设计和需求中存在的错误。需要用单元测试检验被测代码的一个很小的、明确的功能是否正确。
本文主要介绍NAPI框架代码生成工具unit单元测试使用指导。

## 目录

	├── napi_generator                           # NAPI框架代码生成工具
	│   ├── src                                  # 工具源码
	│   ├── ...                                  # 其他文件夹
	│   ├── test                                 # 测试用例
	│   |   ├── ...                              # 其他文件夹
	│   |   ├── unittest                         # 单元测试代码
	│   |   |   ├── analyze.test.js              #执行gen/analyze目录下函数测试用例 
	│   |   |   ├── basic.d.ts*                  #基础函数模板
	│   |   |   ├── extend.test.js*              #执行gen/extend目录下函数测试用例 
	│   |   |   ├── generate.test.js*            #执行gen/generate目录下函数测试用例 
	│   |   |   ├── napi_generator.test.js*      #执行全部测试用例
	│   |   |   ├── '@ohos.input_sample.d.ts'*   #接口、函数等定义模板
	│   |   |   ├── README_ZH.md                 # 测试用例使用指导
	│   |   |   └── tools.test.js*               #执行gen/tools目录下函数测试用例
	 
## 软件环境准备

系统：建议Ubuntu 20.04

依赖版本：python3.8

步骤一：

napi_generator目录下安装以下依赖：

1.下载node_modules包。

	npm i

2.导入rewire模块。

	npm i rewire

步骤二：

napi_generator/src目录下安装以下依赖：

1.下载node_modules包。

	npm i  

## 使用说明

进入napi_generator/目录：

1.执行所有用例，命令为：

	npx mocha test/unittest/

2.执行单个目录用例,如analyze，命令为：

	npx mocha test/unittest/analyze.test.js

## 查看结果

红色：用例执行失败，代表修改的代码有bug或者用例的输出发生变化，需要修复bug或修改用例。

绿色：用例执行成功。

## 相关仓

暂无
