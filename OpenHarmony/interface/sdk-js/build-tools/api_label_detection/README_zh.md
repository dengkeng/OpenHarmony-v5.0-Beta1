# 元服务API集标签检测工具

## 简介
对于元服务标签@atomicservice的漏标误标场景做出识别，辅助API标签排查，将不符合规定标签详情信息汇总至Excel表格中输出.也可根据需求对@form、@crossplatform标签进行校验

## 目录

```
├─src         #存放源码
└─test        #本地运行使用文件
```

## 环境

1)python-3.11.4-amd64

2)PyCharm Community Edition 2023.2

3)需要把src目录设置为sources root(找到src目录，点击右键，将目标标记为里面)

4)在interface_sdk-js目录下运行的是src目录下的mian.py文件

## 运行

检测工具内置在 ‘基础api解析工具’中，通过命令行形式运行。具体命令格式为：

```
python 检测工具main函数位置 -N 工具名称 -L 需要检查的标签(标签名称使用'-'分开，如果需要校验3个标签，当前命令为'all') -P 基础api解析工具结果json文件地址 -O 输Excel出地址

例如需要校验@atomicservice标签和@form标签：python E:\\api_label_detection\\src\\main.py -N detection -L atomicservice-form -P E:\\collect_2024_02_29.json -O D:\\error.xlsx

例如仅校验@atomicservice标签：python E:\\api_label_detection\\src\\main.py -N detection -L atomicservice -P E:\\collect_2024_02_29.json -O D:\\error.xlsx

例如需要校验@atomicservice、@form、@crossplatform标签：python E:\\api_label_detection\\src\\main.py -N detection -L all -P E:\\collect_2024_02_29.json -O D:\\error.xlsx
```

