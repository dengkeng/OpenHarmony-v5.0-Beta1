# NAPI框架代码生成工具

## 版本规划

2024.03.30提供1.4.1版本 基本完善工具C++支持能力,具体特性见表1。

**表 1**  2024.03.30待支持特性

<a name="table143385853320"></a>

<table><thead align="left"><tr id="row53375863312"><th class="cellrowborder" valign="top" width="25%" id="mcps1.2.3.1.1"><p id="p20331858193317"><a name="p20331858193317"></a><a name="p20331858193317"></a>类别</p>
</th>
<th class="cellrowborder" valign="top" width="45%" id="mcps1.2.3.1.2"><p id="p1133115820331"><a name="p1133115820331"></a><a name="p1133115820331"></a>待开发特性</p>
</th>
</tr>
</thead>
<tbody><tr id="row333115812331"><td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.3.1.1 "><p id="p2142111345714"><a name="p2142111345714"></a><a name="p2142111345714"></a>变量/返回值</p>
</td>
<td class="cellrowborder" valign="top" width="45%" headers="mcps1.2.3.1.2 "><a name="ul9264132010"></a><a name="ul9264132010"></a><ul id="ul9264132010"><li>支持ts接口文件中namespace域的any类型之复合类型变量转换为对应C++类型变量 </li><li>支持ts接口文件中namespace域的多中类型合并成新类型之复合类型的变量转换为对应C++类型变量</li></ul>
</td>
</tr>
<tr id="row334175803317"><td class="cellrowborder" valign="top" width="25.77%" headers="mcps1.2.3.1.1 "><p id="p382391145710"><a name="p382391145710"></a><a name="p382391145710"></a>函数</p>
</td>
<td class="cellrowborder" valign="top" width="74.22999999999999%" headers="mcps1.2.3.1.2 "><a name="ul334485413318"></a><a name="ul334485413318"></a><ul id="ul334485413318"><li>支持箭头函数的参数是回调函数</li><li>支持on/off第二个参数为object</li><li>支持class中有参构造中有枚举类型</li><li>箭头回调支持异步调用</li><li>on注册回调的箭头函数支持携带js返回值给C++</li><li>支持js业务代码回调接口中的回调js函数</li><li>class2声明在class1之后时,支持class1中的有参构造的参数有class2</li></ul>
</td>
<tr id="row119944512385"><td class="cellrowborder" valign="top" width="25.77%" headers="mcps1.2.3.1.1 "><p id="p919862210573"><a name="p919862210573"></a><a name="p919862210573"></a>文件</p>
</td>
<td class="cellrowborder" valign="top" width="74.22999999999999%" headers="mcps1.2.3.1.2 "><a name="ul12374158862"></a><a name="ul12374158862"></a><ul id="ul12374158862"><li>优化VSCode插件用户界面</li><li>分离生成的工具代码普通方法和回调方法，防止嵌套使用头文件</li></ul>
</td>
</tr>
</tr>
<tr id="row119944512385"><td class="cellrowborder" valign="top" width="25.77%" headers="mcps1.2.3.1.1 "><p id="p919862210573"><a name="p919862210573"></a><a name="p919862210573"></a>可维护性</p>
</td>
<td class="cellrowborder" valign="top" width="74.22999999999999%" headers="mcps1.2.3.1.2 "><a name="ul12374158862"></a><a name="ul12374158862"></a><ul id="ul12374158862"><li>增加debug信息</li></ul>
</td>
</tr>
</tr>
</tbody>
</table>


## 相关链接

无
