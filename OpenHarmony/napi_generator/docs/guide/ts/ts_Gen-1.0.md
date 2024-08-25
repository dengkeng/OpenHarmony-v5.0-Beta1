# ts_Gen-1.0（2023-01-30）

## 版本概述<a name="section249611124916"></a>

发布ts_Gen-1.0。

## 版本特性<a name="section249611124917"></a>

**表 1**  已支持特性

<a name="table143385853320"></a>

<table><thead align="left"><tr id="row53375863312"><th class="cellrowborder" valign="top" width="15%" id="mcps1.2.3.1.1"><p id="p20331858193317"><a name="p20331858193317"></a><a name="p20331858193317"></a>类别</p>
</th>
<th class="cellrowborder" valign="top" width="60%" id="mcps1.2.3.1.2"><p id="p1133115820331"><a name="p1133115820331"></a><a name="p1133115820331"></a>支持特性</p>
</th>
<th class="cellrowborder" valign="top" width="25%" id="mcps1.2.3.1.3"><p id="p1133115820332"><a name="p1133115820332"></a><a name="p1133115820332"></a>入口平台</p>
</th>
</tr>
</thead>
<tbody><tr id="row333115812331"><td class="cellrowborder" valign="top" width="15%" headers="mcps1.2.3.1.1 "><p id="p2142111345714"><a name="p2142111345714"></a><a name="p2142111345714"></a>变量/返回值</p>
</td>
<td class="cellrowborder" valign="top" width="60%" headers="mcps1.2.3.1.2 "><a name="ul9264132010"></a><a name="ul9264132010"></a><ul id="ul9264132010"><li>支持C++语言中string、std::string、char、wchar_t、char16_t、char32_t、short、int、int16_t、uint16_t、int32_t、uint32_t、int64_t、uint64_t、double_t、float_t、size_t、long、long long、float、double、long double、bool基础类型的变量/函数入参自动转换为对应TS接口中变量/入参</li><li>支持C++语言中string、std::string、char、wchar_t、char16_t、char32_t、short、int、int16_t、uint16_t、int32_t、uint32_t、int64_t、uint64_t、double_t、float_t、size_t、long、long long、float、double、long double、bool数组类型的变量/函数入参自动转换为对应TS接口中变量/入参，数组书写方式为std::vector<></li><li>支持C++语言string、std::string、char、wchar_t、char16_t、char32_t、short、int、int16_t、uint16_t、int32_t、uint32_t、int64_t、uint64_t、double_t、float_t、size_t、long、long long、float、double、long double、bool基础类型的返回值自动转换为对应TS接口中返回值</li></ul>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.3.1.3 "><a name="ul9264132011"></a><a name="ul9264132011"></a><ul id="ul9264132011"><li>可执行文件-Windows/Ubuntu/Mac</li><li>IntelliJ插件-Windows</li></ul>
</td>
</tr>
<tr id="row334175803317"><td class="cellrowborder" valign="top" width="15%" headers="mcps1.2.3.1.1 "><p id="p382391145710"><a name="p382391145710"></a><a name="p382391145710"></a>函数类型</p>
</td>
<td class="cellrowborder" valign="top" width="60%" headers="mcps1.2.3.1.2 "><a name="ul334485413318"></a><a name="ul334485413318"></a><ul id="ul334485413318"><li>支持ts接口文件中namespace域的static函数自动转换为对应TS接口中的函数</li></ul>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.3.1.3 "><a name="ul9264132013"></a><a name="ul9264132013"></a><ul id="ul9264132013"><li>可执行文件-Windows/Ubuntu/Mac</li><li>IntelliJ插件-Windows</li></ul>
</td>
</tr>
<tr id="row834358143319"><td class="cellrowborder" valign="top" width="15%" headers="mcps1.2.3.1.1 "><p id="p1818191195713"><a name="p1818191195713"></a><a name="p1818191195713"></a>class</p>
</td>
<td class="cellrowborder" valign="top" width="60%" headers="mcps1.2.3.1.2 "><a name="ul4367144411512"></a><a name="ul4367144411512"></a><ul id="ul4367144411512"><li>支持C++语言中class的变量、函数自动转换为对应TS接口中的变量、函数</li></ul>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.3.1.3 "><a name="ul9264132015"></a><a name="ul9264132015"></a><ul id="ul9264132015"><li>可执行文件-Windows/Ubuntu/Mac</li><li>IntelliJ插件-Windows</li></ul>
</td>
</tr>
<tr id="row119944512385"><td class="cellrowborder" valign="top" width="15%" headers="mcps1.2.3.1.1 "><p id="p919862210573"><a name="p919862210573"></a><a name="p919862210573"></a>namespace</p>
</td>
<td class="cellrowborder" valign="top" width="60%" headers="mcps1.2.3.1.2 "><a name="ul12374158862"></a><a name="ul12374158862"></a><ul id="ul12374158862"><li>支持C++语言中namespace域的变量、函数自动转换为对应TS接口中的变量、函数</li><li>支持.h文件中namespace域class转换为对应TS接口中的class</li> </ul>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.3.1.3 "><a name="ul9264132017"></a><a name="ul9264132017"></a><ul id="ul9264132017"><li>可执行文件-Windows/Ubuntu/Mac</li><li>IntelliJ插件-Windows</li></ul>
</td>
</tr>
<tr id="row18711154213388"><td class="cellrowborder" valign="top" width="15%" headers="mcps1.2.3.1.1 "><p id="p111921822185713"><a name="p111921822185713"></a><a name="p111921822185713"></a>文件</p>
</td>
<td class="cellrowborder" valign="top" width="60%" headers="mcps1.2.3.1.2 "><a name="ul94024441879"></a><a name="ul94024441879"></a><ul id="ul94024441879"><li>支持.h文件中namespace数据类型转换为对应TS接口中的数据类型</li><li>支持C++文件名格式A.h的文件转换</li><li>支持命令行方式转换时参数为多个文件路径，相互之间用英文逗号分开</li><li>支持命令行方式转换时指定文件夹路径方式转换</li></ul>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.3.1.3 "><a name="ul9264132019"></a><a name="ul9264132019"></a><ul id="ul9264132019"><li>可执行文件-Windows/Ubuntu/Mac</li><li>IntelliJ插件-Windows</li></ul>
</td>
</tr>
</tbody>
</table>

**表 2** 

[待开发特性](https://gitee.com/openharmony/napi_generator/blob/master/docs/guide/ts/ROADMAP_ZH.md)