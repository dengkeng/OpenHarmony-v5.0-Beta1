# TS生成工具使用说明

## 简介

TS(type-script)接口生成工具，它可以根据定义在c++头文件中的接口，生成type-script语言的TS接口文件。若某个服务实现方式为c++，且供应用层访问的接口已在.h文件中定义，此时，NAPI接口开发者使用此工具可一键生成对应的ts文件，进而将生成的TS文件作为NAPI框架生成代码工具的输入，生成NAPI框架代码。

## 约束

visual studio code 版本需1.62.0及以上。

## 操作简介

1.安装VS Code插件。

2.打开任意文件夹或文件，鼠标单击右键选择“Generate Ts Frame”插件。

3.在窗口中填写相应参数。

详细说明见

[TS接口生成使用说明](https://gitee.com/openharmony/napi_generator/blob/master/hdc/ts/ts_vs_plugin/docs/INSTRUCTION_ZH.md)

## 合作共建

[联系方式](https://www.kaihong.com/)
