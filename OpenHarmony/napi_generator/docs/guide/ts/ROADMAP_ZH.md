# TS接口文件生成工具

## 版本规划

2023.08.30提供1.1版本 基本完善工具C++支持能力，具体特性见表1。

**表 1**  2023.08.30待支持特性

<a name="table143385853320"></a>

<table><thead align="left"><tr id="row53375863312"><th class="cellrowborder" valign="top" width="15%" id="mcps1.2.3.1.1"><p id="p20331858193317"><a name="p20331858193317"></a><a name="p20331858193317"></a>类别</p>
</th>
<th class="cellrowborder" valign="top" width="55%" id="mcps1.2.3.1.2"><p id="p1133115820331"><a name="p1133115820331"></a><a name="p1133115820331"></a>待开发特性</p>
</th>
<th class="cellrowborder" valign="top" width="30%" id="mcps1.2.3.1.3"><p id="p1133115820332"><a name="p1133115820332"></a><a name="p1133115820332"></a>入口平台</p>
</th>
</tr>
</thead>
<tbody><tr id="row333115812331"><td class="cellrowborder" valign="top" width="15%" headers="mcps1.2.3.1.1 "><p id="p2142111345714"><a name="p2142111345714"></a><a name="p2142111345714"></a>变量/返回值</p>
</td>
<td class="cellrowborder" valign="top" width="55%" headers="mcps1.2.3.1.2 "><a name="ul9264132010"></a><a name="ul9264132010"></a><ul id="ul9264132010"><li>支持C++语言中enum复合类型变量/函数入参自动转换为对应TS接口中的变量/函数 </li><li>支持C++语言中std::map转换为对应TS接口中的Map<></li><li>支持C++语言中std::any转换为对应TS接口中的any</li><li>支持C++语言中namespace域嵌套namespace转换为对应TS接口中的实现</li><li>支持C++语言数组类型为using定义的NUMBER_TYPE类型转换为对应TS接口中的变量</li></ul>
</td>
<td class="cellrowborder" valign="top" width="30%" headers="mcps1.2.3.1.3 "><a name="ul9264132011"></a><a name="ul9264132011"></a><ul id="ul9264132011"><li>可执行文件-Windows/Ubuntu/Mac</li><li>IntelliJ插件-Windows</li><li>VSCode插件-Windows/Ubuntu/Mac</li></ul>
</td>
</tr>
<tr id="row334175803317"><td class="cellrowborder" valign="top" width="15%" headers="mcps1.2.3.1.1 "><p id="p382391145710"><a name="p382391145710"></a><a name="p382391145710"></a>namespace</p>
</td>
<td class="cellrowborder" valign="top" width="55%" headers="mcps1.2.3.1.2 "><a name="ul334485413318"></a><a name="ul334485413318"></a><ul id="ul334485413318"><li>支持.h文件中namespace域class继承转换为对应TS文件中继承的class</li></ul>
</td>
<td class="cellrowborder" valign="top" width="30%" headers="mcps1.2.3.1.3 "><a name="ul9264132012"></a><a name="ul9264132012"></a><ul id="ul9264132012"><li>可执行文件-Windows/Ubuntu/Mac</li><li>IntelliJ插件-Windows</li><li>VSCode插件-Windows/Ubuntu/Mac</li></ul>
</td>
</tr>
</tr>
</tbody>
</table>


## 相关链接

无

