# 录制测试用例归档

## 用例表

|测试功能|预置条件|输入|预期输出|测试结果|
|--------------------------------|--------------------------------|--------------------------------|--------------------------------|--------------------------------|
|拉起应用|	设备正常运行|		|成功拉起应用|Pass|
|允许权限| 设备正常运行 | 点击权限弹窗允许按钮 |授权后成功进入首页|Pass|
|音频录制参数选择| 位于音频录制页面 | 1、点击首页**设置**按钮<br/>2、选择配置参数，点击确定<br/> |参数设置成功|Pass|
| 音频录制状态切换 | 位于音频录制页面 | 1、点击**开始**按钮，录制2s<br/>2、点击**暂停**按钮<br/>3、点击**继续**按钮，录制1s<br/>4、点击**停止**按钮<br/> | 1、进入录制中状态<br/>2、进入暂停状态<br/>3、重新恢复录制中状态<br/>4、停止录制恢复初始状态<br/> |Pass|

