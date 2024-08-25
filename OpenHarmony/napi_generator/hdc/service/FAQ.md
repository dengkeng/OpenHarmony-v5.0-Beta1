# SERVICE生成工具 问题反馈

## 问题反馈

1、使用工具生成service框架代码时，报错“ EEXIST: file already exists, mkdir 'out\examservice'”。

![](./figures/file_already_exists.png)

问题定位：在使用工具生成service框架代码之前，指定目录下已存在.h文件中class对应的框架代码文件，因此生成失败。

问题解决：修改.h文件中class名称，或删除对应框架代码都可以解决该问题。

