将相关文件按规则解析成特定格式，提供处理接口

## 目录

```

├─src				#工具代码
|  ├─bin			#命令行执行配置
|  |  ├─config.ts
|  |  ├─index.ts
|  |  └─writer.ts
|  ├─coreImpl			#工具实现的功能及接口
|  |  ├─checker			#检查声明文件中的格式规范
|  |  |  ├─config			#存放检查工具运行所需要的一些配置文件
|  |  |  ├─src				    #工具代码
|  |  |  ├─local_entry.ts	#检查工具入口文件
|  |  ├─diff			#比较两个版本sdk差异的工具
|  |  |  ├─diff.ts			#实现工具的对外接口
|  |  |  ├─DiffProcessor.ts
|  |  |  └─PermissionsProcessor.ts	#逻辑运算工具，用于判断权限范围变化
|  |  ├─parser			#基础解析工具
|  |  |  ├─JsDocProcessor.ts
|  |  |  ├─NodeProcessor.ts
|  |  |  ├─parser.ts			#实现工具的对外接口
|  |  |  └─ResultsProcess.ts		#将parser解析完的结果处理为其他接口需要的格式
|  |  └─statistics		#api统计工具
|  |     └─Statistics.ts
|  ├─typedef			#每个工具中class，type的定义
|  |  ├─diff
|  |  |  └─ApiInfoDiff.ts
|  |  ├─parser
|  |  |  ├─ApiInfoDefination.ts
|  |  |  ├─comment.ts
|  |  |  └─ResultsInfo.ts
|  |  └─statistics
|  |     └─ApiStatistics.ts
|  ├─utils			#通用方法
|  |  ├─Constant.ts		#全局静态常量
|  |  ├─FileUtils.ts		#文件工具
|  |  ├─logUtil.ts		#log日志工具
|  |  ├─FunctionUtils.ts	#公共方法
|  |  └─StringUtils.ts		#字符串数据处理工具
|  └─main.ts			#commander调用入口
├─test				#工具自动化测试配置及用例
|  ├─expect				#测试用例结果检验，与测试用例输出结果进行对比，每个工具单独新建子文件
|  ├─mocha				#mocha相关配置
|  ├─output				#测试用例执行输出结果
|  ├─testCase				#测试用例调用工具接口
|  |  └─runTest.ts
|  └─ut					#测试用例，每个工具单独新建子文件

```

## 工具说明

### 基础解析工具

[代码](src/coreImpl/parser/parser.ts)

提供接口

1. parseDir(fileDir)
   解析一个文件夹下的文件，返回所有数据
2. parseFile(fileDir,filePath)
   解析单个文件，fileDir为根节点，需要用来计算相对路径
3. getApiInfo(locations,apiMap)
   将层级关系和通过上述两个接口的返回值可以直接获取对应节点
4. getParseResults(apiMap)
   将接口1、2的树形结构的数据遍历展开
5. getParseEachSince(apiMap)
   将接口1、2的树形结构的数据遍历展开，进行特殊处理，根据since来区分子节点

### check工具

[代码](src/coreImpl/checker/local_entry.ts)

提供接口

1. checkEntryLocal(filePath, fileRule, output, excel)
   根据传入的文件路径和检查规则检查文件中存在的规范错误

工具调用命令

```
node --nolazy -r ts-node/register ./src/main.ts -N checkOnline --path 待检查文件路径（非build-tools） --checker 检查规则  --output 报告输出目录 --excel false
```

### diff工具

[代码](src/coreImpl/diff/diff.ts)

提供接口

1. diffSDK(oldSDKApiMap,newSDKApiMap)
   将两个版本的文件通过基础解析工具解析之后，传入两个结果计算diff

工具调用命令

```
node --nolazy -r ts-node/register ./src/main.ts -N diff --old 旧版本目录/文件（sdk/windows/ets） --new 新版本目录/文件（sdk/windows/ets) --old-version 旧版本号 --new-version 新版本号 --output 报告输出目录 --format excel
```

### api统计工具

[代码](src/coreImpl/statistics/ApiStatistics.ts)

提供接口

1. getApiStatisticsInfos(apiMap)
   将文件通过基础解析工具解析之后，传入计算api接口

工具调用命令

```
node --nolazy -r ts-node/register ./src/main.ts -N collect -C 目录路径/文件路径 --output 报告输出目录 --format excel
```

### 元服务API集标签检测工具

[代码](..\api_label_detection\src\main.py)

对于元服务标签@atomicservice的漏标误标场景做出识别，辅助API标签排查，将不符合规定标签详情信息汇总至Excel表格中输出.也可根据需求对@form、@crossplatform标签进行校验

工具调用命令

```
node --nolazy -r ts-node/register ./src/main.ts -N detection -L 验证标签 -C api全文件 -F 统计目录/文件 -O 报告输出目录
```

详细内容见[元服务API集标签检测工具](..\api_label_detection\README_zh.md)

## 工具xiangx调用

通过commander调用相关工具，[调用入口](src/main.ts)只有（src/main.ts），到当前目录下，执行命令 ts-node ./src/main.ts 后接相关参数。

### 参数配置

  -N,--tool-name <collect, diff>     tool name  (default: "collect")
  -V, --version                      output the version number
  -C,--collect-Path `<string>`         collect api path (default: "./api")
  --path `<string>`                    check file path
  --checker `<string>`                 check file rule
  --excel `<string>`                   check ouput file contain excel
  --old `<string>`                     diff old sdk path (default: "./api")
  --new `<string>`                     diff new sdk path (default: "./api")
  --old-version `<string>`             old sdk version (default: "0")
  --new-version `<string>`             new sdk version (default: "0")
  --output `<string>`                  output file path (default: "./")
  --format <json, excel, changelog>  output file format (default: "json")
  --changelogUrl `<string>`            changelog url (default: "")
  -h, --help                         display help for command

例如

```
ts-node ./src/main.ts '-N' 'diff' '-C' '.\test\ut\parser\ut_jsdoc_constant_001.d.ts' '--old' '.\test\ut\apiDiff\old\ut_api_name_change.d.ts' '--new' '.\test\ut\apiDiff\new\ut_api_name_change.d.ts' '--old-version' '1' '--new-version' '2' '--output' '.\'
```

```
node --nolazy -r ts-node/register ./src/main.ts '-N' 'diff' '-C' '.\test\ut\parser\ut_jsdoc_constant_001.d.ts' '--old' '.\test\ut\apiDiff\old\ut_api_name_change.d.ts' '--new' '.\test\ut\apiDiff\new\ut_api_name_change.d.ts' '--old-version' '1' '--new-version' '2' '--output' '.\'
```

```
node ./package/JS_API_OPTIMIZE_PLUGIN.js  '-N' 'diff' '-C' '.\test\ut\parser\ut_jsdoc_constant_001.d.ts' '--old' '.\test\ut\apiDiff\old\ut_api_name_change.d.ts' '--new' '.\test\ut\apiDiff\new\ut_api_name_change.d.ts' '--old-version' '1' '--new-version' '2' '--output' '.\'
```

## 工具开发注意事项

1、禁止全量工具使用__dirname

可以通过import  src\utils\FileUtils.ts，通过FileUtils.getBaseDirName，获取当前项目的根目录，之后在通过文件相对路径获取文件

## 项目启动

项目分为线上运行和线下运行

### 本地运行

1. 先确认本地node版本是否为14版本，本工具只支持使用14版本的node
2. 运行以下脚本安装相关依赖

```
npm install
```

安装完成之后根据目录和注意事项完成工具开发或测试

### 线上运行

线上存在需要打包生成bundle.js文件

1、安装依赖，在全量仓下执行安装依赖命令

```
npm install
```

2、执行打包命令，将ts打包为js

```
npm run build
```

执行完之后生成./package/JS_API_OPTIMIZE_PLUGIN.js

3、根据上方的工具调用说明，通过node和参数来调用相关方法

例如

```
node ./package/JS_API_OPTIMIZE_PLUGIN.js '-N' 'diff' '-C' '.\test\ut\parser\ut_jsdoc_constant_001.d.ts' '--old' '.\test\ut\apiDiff\old\ut_api_name_change.d.ts' '--new' '.\test\ut\apiDiff\new\ut_api_name_change.d.ts' '--old-version' '1' '--new-version' '2' '--output' '.\'
```
