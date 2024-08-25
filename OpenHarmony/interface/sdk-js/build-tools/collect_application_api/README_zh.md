# 工具使用说明

## 使用方式

### 使用工具源码扫描

1. [下载应用API解析工具源码](https://gitee.com/openharmony/interface_sdk-js/tree/master/build-tools/collect_application_api)

2. 在package.json同级目录下执行npm install安装依赖

3. 在package.json同级目录下运行工具：

   扫描单个应用，例：

   ```
   node .\src\entry\main.js --app 工程根目录 --sdk sdk根目录/9/ets  --output 报告的输出路径 --format excel
   ```

   扫描多个应用，例：

   ```
   node .\src\entry\main.js --appDir --sdkRoot sdk根目录 --output 报告的输出路径 --format excel
   ```

### 使用工具包扫描

1. [下载应用API解析工具源码](https://gitee.com/openharmony/interface_sdk-js/tree/master/build-tools/collect_application_api)
2. 在package.json同级目录下执行npm install安装依赖
3. 使用：npm run build进行打包，打包成功后，会生成dist文件夹，文件夹下的apiCollector压缩包即为打包后的工具

#### 工具包结构

```
apiCollector-x.x.x.zip
|- libs // ES库
|- api-collector.js // 执行脚本
```

查看工具命令行参数，**api-collector.js 需要指定路径，以下例子命令行默认在解压目录下执行**

```shell
node api-collector.js -h
```

```shell
Usage: api-collector [options]

collect api from app's source code.

Options:
  -V, --version          output the version number
  --app <string>         app root directory
  --appDir <string>      a path that contains multiple applications
  --sdk <string>         sdk path, need to specify the ets directory, e.g sdk-root/version/ets
  --sdkRoot <string>     sdk root path
  --output <string>      the path to output the report
  --format <json,excel>  format of the output report
  --scanTest             scan ohosTest
  --debug                output debug logs
  --noRepeat             apiInfos is not repeat
  -h, --help             display help for command
```

工具输出 app_api.xlsx 或者 collectedApi.json，具体格式和路径取决于 --format, --output 参数

#### 扫描单个应用

```shell
node api-collector.js --app 工程根目录 --sdk sdk根目录/9/ets  --output 报告的输出路径 --format excel
```

上述命令的行为：

1. 解析 local.properties 获取 sdk 根目录
2. 解析 build-profile.json5 获取 sdk 版本
3. 拼接完整 sdk 路径，指向到 sdk 目录下的 ets 目录
4. 扫描 build-profile.json5 中 modules 下的代码目录

上述命令执行时可能存在 local.properties 文件不存在，导致 sdk 根目录无法获取，此时需要使用 --sdkRoot 指定 sdk 根目录

```shell
node api-collector.js --app 工程根目录 --sdkRoot sdk根目录
```

上述命令执行时还可能存在 build-profile.json5 文件找不到，或者无法解析到 sdk 的版本号，此时需要 --sdk 指定 sdk 目录中 ets 目录的路径

```shell
node api-collector.js --app 工程根目录 --sdk sdk根目录/9/ets
```

#### 扫描目录下的多个应用

```shell
node .\src\entry\main.js --appDir --sdkRoot sdk根目录 --output 报告的输出路径 --format excel
```

上述命令的行为：

1. 搜集目录下所有工程路径
2. 遍历所有工程路径，按单个应用的方式进行扫描

因此，上述命令也可能会遇到 sdk 路径无法识别的问题, 可以通过 --sdkRoot 指定 sdk 根目录

```shell
node api-collector.js --appDir 文件夹路径 --sdkRoot sdk根目录
```

扫描多个应用不支持 --sdk 参数，因为 --sdk 参数限定了 sdk 的版本号，而每个应用的版本号并不一致。批量扫描应用时，sdk 的版本号统一从 build-profile.json5 中 compileSdkVersion 字段获取，若 build-profile.json5 文件不存在或 compileSdkVersion 没有，则跳过此工程。

## 指令参数

--output 指定扫描报告的输出路径，不指定则默认输出在应用工程根目录

--format 指定扫描报告的格式, 支持 excel, json，默认为 excel 表格

--scanTest 扫描 ohosTest 目录下的代码

--debug 打开debug日志