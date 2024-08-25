# JSDoc format

## 简介

此工具可以将 d.ts 声明文件进行格式化处理并输出新的 d.ts 声明文件。

## 使用方法

* 调试阶段

  ```shell
  npm install
  ts-node ./src/main.ts -i input.d.ts -o output.d.ts
  ```

  命令行参数：

  -i：指定需要格式化的 d.ts 文件或者包含 d.ts 文件的目录

  -o：指定新文件的名字或者输出目录

  注意：-i 指定的是文件，则 -o 参数需要指向文件。-i 指定的是目录，-o 参数需要指向目录。

* 打包成 bundle(bundle.js 是可以独立运行的完整工具)

  ```shell
  npm run build
  node build/bundle.js -i input.d.ts -o output.d.ts
  ```

  bundle.js 在 build 目录下，命令行参数与调试阶段一样。

完整的命令行参数可通过 -h 参数获得：

```shell
Usage: jsdoc-tool [options]

CLI to format d.ts

Options:
  -V, --version                         output the version number
  -i, --input <path>                    d.ts文件或包含d.ts的文件夹
  -o, --output <path>                   新的d.ts输出文件或目录
  -l, --logLevel <INFO,WARN,DEBUG,ERR>  日志输出级别[INFO,WARN,DEBUG,ERR] (default: "INFO")
  -s, --split                           是否拆分接口 (default: false)
  -h, --help                            display help for command
```

## 报告

在上述命令成功执行完后，会同时生成一个 .xlsx 报告。可根据报告提示，修改错误。

报告出现在 -i 输入的文件/文件夹的同级目录，命名方式为 文件(夹)名_时间戳.xlsx
