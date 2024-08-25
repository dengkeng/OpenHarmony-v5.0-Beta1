## NAPI 开发教程

### 背景

#### Node-API 介绍

Node-API（以前称为 N-API）是用于构建原生插件的 API。它独立于底层 JavaScript 运行时，并作为 ’Node‘.js 本身的一部分进行维护。此 API 将在 ’Node‘.js 的各个版本中保持稳定的应用二进制接口 (ABI)。它旨在将插件与底层 JavaScript 引擎的变化隔离开来，并允许为一个主要版本编译的模块无需重新编译即可在以后的 ’Node‘.js 主要版本上运行。[ABI 稳定性](docs/guides/abi-stability/) 指南提供了更深入的解释。

插件是使用标头为 [C++ 插件](api/addons.html) 的部分中概述的相同方法/工具构建/打包的。唯一的区别是原生代码使用的 API 集。

Node-API 公开的 API 通常用于创建和操作 JavaScript 值。概念和操作通常映射到 ECMA-262 语言规范中指定的想法。API 具有以下属性：

- 所有 Node-API 调用都会返回 `napi_status` 类型的状态代码。此状态指示 API 调用是成功还是失败。

- API 的返回值通过 out 参数传递。

- 所有 JavaScript 值都被抽象为一个名为 `napi_value` 的不透明类型。

- 如果出现错误状态代码，可以使用 `napi_get_last_error_info` 获取附加信息。可以在错误处理部分 [错误处理](api/n-api.html#error-handling) 中找到更多信息。


Node-API 是一种 C API，可确保跨版本和不同编译器级别的 ABI 稳定性。C++ API 可以更容易使用。为了支持使用 C++，该项目维护了一个名为 `node-addon-api` 的 C++ 封装器模块。这个封装器提供了一个可内联的 C++ API。使用 `node-addon-api` 构建的二进制文件将取决于 导出的基于 Node-API C 的函数的符号。`node-addon-api` 是编写调用 Node-API 的代码的更有效方式。



---



#### Native API（NativeDevelopKit）

Native API是OpenHarmony SDK上提供的一组native开发接口与工具集合（也称为NativeDevelopKit），方便开发者使用C或者C++语言实现应用的关键功能。Native API只覆盖了OHOS基础的一些底层能力，如libc，图形库，窗口系统，多媒体，压缩库等，并没有完全提供类似于JS API上的完整的OHOS 平台能力。在应用中使用Native API会编译成动态库打包到应用中。



##### 名词概念

| 名词       | 名词解释                                                     |
| :--------- | :----------------------------------------------------------- |
| Native API | OHOS SDK里面native包提供的，面向三方应用开发的Native 接口以及相应编译脚本，编译工具链。包括C运行时基础库libc，3D图形库opengl，面向JS与C跨语言的接口Node-API等，具体内容详见下表。 |
| NativeDevelopKit        | Native Develop Kit的缩写，在OHOS上就是Native API；Native API是官方名字，NativeDevelopKit指代相同意思。 |
| SDK CAPI   | OHOS Native API中的C语言接口，以及工具链部分，当前OHOS的Native API里面只包含C语言接口，因此Native API与CAPI意思一样，建议交流的时候使用CAPI，防止Native API与napi缩写混用。 |
| Node-API   | 曾用名napi，是OHOS中提供JS与C跨语言调用的接口，是Native API接口中的一部分. 该接口在’Node‘.js提供的Node-API基础上扩展而来，但不完全与’Node‘.js中的Node-API完全兼容。 |
| napi       | Node-API的曾用名，当前Node-API头文件中的接口仍然以napi_开头，不建议使用。 |



##### Native API构成介绍

* 目录结构

  Native API在SDK包的位置为$(SDK_ROOT)/native目录，主要有以下几个部分组成

  | 目录        | 功能说明                                                     |
  | :---------- | :----------------------------------------------------------- |
  | build       | 应用中编译动态库的toolchain cmake脚本；这个目录下ohos.toolchain.cmake文件定义了给OHOS交叉编译选项 |
  | build-tools | 放置编译构建的工具，如cmake                                  |
  | docs        | Native API接口参考文档，通过doxgen从头文件中提取出来         |
  | sysroot     | 放置编译链接的依赖文件目录，包含头文件，动态库等             |

* API接口

  | 接口分类                                                     | 接口功能                                                     | 引入版本 |
  | :----------------------------------------------------------- | :----------------------------------------------------------- | :------- |
  | [标准C库](https://docs.openharmony.cn/pages/v4.0/zh-cn/application-dev/reference/native-lib/third_party_libc/muslc.md) | 以muslc为基础提供的标准c库接口，当前提供了1500+的接口         | 8        |
  | [标准C++库](https://docs.openharmony.cn/pages/v4.0/zh-cn/application-dev/reference/native-lib/third_party_libc/cpp.md) | c++运行时库libcpp_shared，此库在打包的时候需要打包或者静态链接到应用中 | 8        |
  | 日志                                                         | 打印日志到系统的hilog接口                                    | 8        |
  | Node-API                                                     | ArkUI提供的，方便应用开发接入JS应用环境的一组类Node-API（也叫napi），是属于Native API的一部分 | 8        |
  | XComponent                                                   | ArkUI XComponent组件中的界面与触屏事件接口，方便开发者开发高性能图形应用 | 8        |
  | libuv                                                        | ArkUI集成的三方的异步IO库                                    | 8        |
  | libz                                                         | zlib库，提供基本的压缩，解压接口                             | 8        |
  | Drawing                                                      | 系统提供的2D图形库，可以在界面进行绘制                    | 8        |
  | OpenGL                                                       | 系统提供的openglv3接口                                       | 8        |
  | Rawfile                                                      | 应用资源访问接口，可以读取应用中打包的各种资源               | 8        |
  | OpenSLES                                                     | 用于2D，3D音频加速的接口库                                   | 8        |
  | Mindspore                                                    | AI模型接口库                                                 | 9        |
  | 包管理                                                       | 包服务接口，方便查询应用包信息                               | 8        |

* 相关资料

  - [Native API参考](https://docs.openharmony.cn/pages/v4.0/zh-cn/application-dev/reference/native-apis/_o_h___native_x_component.md)，介绍各个API参考手册
  - [Native API中支持的标准库](https://docs.openharmony.cn/pages/v4.0/zh-cn/application-dev/reference/native-lib/third_party_libc/muslc.md)，介绍Native API支持的开源标准库
  - [Native API开发指南](https://docs.openharmony.cn/pages/v4.0/zh-cn/application-dev/napi/napi-guidelines.md)，结合具体的例子，场景介绍各类接口的使用
  - [如何在Cmake工程中使用NativeDevelopKit](https://docs.openharmony.cn/pages/v4.0/zh-cn/application-dev/faqs/cmake-with-nativedevkit.md)，介绍如何使用使用NativeDevelopKit开发一个CMake工程
  - [Node-API在应用工程中的使用指导](https://docs.openharmony.cn/pages/v4.0/zh-cn/application-dev/napi/napi-guidelines.md), 如何使用Node-API接口



---



#### 教程介绍

此教程是 Node-API 和 ArkTS 的联合使用版本，展示了如何引入Native-C++的lib库和头文件，然后通过ArkUI进行展示和直接在 OpenHarmony 设备中运行。它为开发人员提供了在 DevEco Studio 开发中使用 lib库和Native-C++ 的能力，并且通过一系列教程来引导用户了解 Native-C++ 中提供的各种功能。

Native-C++ 教程的目的包括：

- 帮助将 Native-C++ 应用于 OpenHarmony 应用开发中
- 帮助 OpenHarmony 社区、开发人员和三方库尤其是C/C++研究人员交互式地访问各种基于 OpenHarmony 的 C/C++ 示例，以帮助理解特定的视觉算法
- 由于 Native-C++ 能够直接在 OpenHarmony 设备中运行，教程页面具有直观和交互式的特点。例如，利用 ArkUI 和 评估 ArkTS 代码，开发人员可以更改 Native-C++ 函数的参数，并在 OpenHarmony 上进行实时的 C/C++ 编程，以实时查看结果。

为了更好地理解这些教程，建议具备一定的 ArkUI，NAPI 和 C++ 应用程序开发知识。通过学习 Native-C++ 教程，开发人员可以更好地利用 Native-C++ 在 OpenHarmony 开发中的优势，并通过交互式的方式进行实时的算法处理，从而加深对 Native-C++和Node-API 的理解和应用能力。



---



#### 步骤

在本教程中，您将学习如何在 OpenHarmony 应用开发里引入和使用 Native API 开发。

请注意，以下是一些步骤供您参考：

1. 使用napitutorials样例工程：

   - IDE版本为：DevEco Studio 4.0 Release（Build Version: 4.0.0.600, built on October 17, 2023）。

     

2. 自行开发nativedevkit应用：

   - 按照 [创建NativeDevelopKit工程]([创建NativeDevelopKit工程 (openharmony.cn)](https://docs.openharmony.cn/pages/v4.0/zh-cn/application-dev/napi/create-with-nativedevkit.md)) 教程中的步骤，配置和构建 native C++ 工程。

     

完成上述步骤后，您就可以在 OpenHarmony 设备上体验 Native API 的能力，并按照 [Node-API]([Node-API | ’Node‘.js v20 文档](api/n-api.html)) 教程进行进一步的学习和实践了。



#### 样例能力

| 模块                             | 接口                                                         | 是否支持 | 备注       |
| -------------------------------- | ------------------------------------------------------------ | -------- | ---------- |
| 环境生命周期API                  | [`napi_set_instance_data`](api/v18/n-api.html#napi_set_instance_data) | 不支持   | 缺少对应库 |
|                                  | [`napi_get_instance_data`](api/v18/n-api.html#napi_get_instance_data) |          |            |
|                                  |                                                              |          |            |
| 基本Node-API数据类型             |                                                              |          |            |
|                                  | [`napi_status`](api/v18/n-api.html#napi_status) |          |            |
|                                  | [`napi_extended_error_info`](api/v18/n-api.html#napi_extended_error_info) |          |            |
|                                  | [`napi_env`](api/v18/n-api.html#napi_env)  |          |            |
|                                  | [`napi_value`](api/v18/n-api.html#napi_value) |          |            |
|                                  | [`napi_threadsafe_function`](api/v18/n-api.html#napi_threadsafe_function) |          |            |
|                                  | [`napi_threadsafe_function_release_mode`](api/v18/n-api.html#napi_threadsafe_function_release_mode) |          |            |
|                                  | [`napi_threadsafe_function_call_mode`](api/v18/n-api.html#napi_threadsafe_function_call_mode) |          |            |
|                                  |                                                              |          |            |
| Node-API内存管理类型             | [`napi_handle_scope`](api/v18/n-api.html#napi_handle_scope) |          |            |
|                                  | [`napi_escapable_handle_scope`](api/v18/n-api.html#napi_escapable_handle_scope) |          |            |
|                                  | [`napi_ref`](api/v18/n-api.html#napi_ref)  |          |            |
|                                  | [`napi_type_tag`](api/v18/n-api.html#napi_type_tag) |          |            |
|                                  | [`napi_async_cleanup_hook_handle`](api/v18/n-api.html#napi_async_cleanup_hook_handle) |          |            |
|                                  |                                                              |          |            |
| Node-API回调类型                 | [`napi_callback_info`](api/v18/n-api.html#napi_callback_info) |          |            |
|                                  | [`napi_callback`](api/v18/n-api.html#napi_callback) |          |            |
|                                  | [`napi_finalize`](api/v18/n-api.html#napi_finalize) |          |            |
|                                  | [`napi_async_execute_callback`](api/v18/n-api.html#napi_async_execute_callback) |          |            |
|                                  | [`napi_async_complete_callback`](api/v18/n-api.html#napi_async_complete_callback) |          |            |
|                                  | [`napi_threadsafe_function_call_js`](api/v18/n-api.html#napi_threadsafe_function_call_js) |          |            |
|                                  | [`napi_cleanup_hook`](api/v18/n-api.html#napi_cleanup_hook) |          |            |
|                                  | [`napi_async_cleanup_hook`](api/v18/n-api.html#napi_async_cleanup_hook) |          |            |
|                                  |                                                              |          |            |
| 错误处理                         |                                                              |          |            |
| 返回值                           | [`napi_get_last_error_info`](api/v18/n-api.html#napi_get_last_error_info) |          |            |
|                                  |                                                              |          |            |
| 异常                             | [`napi_throw`](api/v18/n-api.html#napi_throw) |          |            |
|                                  | [`napi_throw_error`](api/v18/n-api.html#napi_throw_error) |          |            |
|                                  | [`napi_throw_type_error`](api/v18/n-api.html#napi_throw_type_error) |          |            |
|                                  | [`napi_throw_range_error`](api/v18/n-api.html#napi_throw_range_error) |          |            |
|                                  | [`node_api_throw_syntax_error`](api/v18/n-api.html#node_api_throw_syntax_error) |          |            |
|                                  | [`napi_is_error`](api/v18/n-api.html#napi_is_error) |          |            |
|                                  | [`napi_create_error`](api/v18/n-api.html#napi_create_error) |          |            |
|                                  | [`napi_create_type_error`](api/v18/n-api.html#napi_create_type_error) |          |            |
|                                  | [`napi_create_range_error`](api/v18/n-api.html#napi_create_range_error) |          |            |
|                                  | [`node_api_create_syntax_error`](api/v18/n-api.html#node_api_create_syntax_error) |          |            |
|                                  | [`napi_get_and_clear_last_exception`](api/v18/n-api.html#napi_get_and_clear_last_exception) |          |            |
|                                  | [`napi_is_exception_pending`](api/v18/n-api.html#napi_is_exception_pending) |          |            |
|                                  | [`napi_fatal_exception`](api/v18/n-api.html#napi_fatal_exception) |          |            |
|                                  |                                                              |          |            |
| 致命错误                         | [`napi_fatal_error`](api/v18/n-api.html#napi_fatal_error) |          |            |
|                                  |                                                              |          |            |
| 对象生命周期管理                 |                                                              |          |            |
| 使句柄寿命短于本地方法           | [`napi_open_handle_scope`](api/v18/n-api.html#napi_open_handle_scope) |          |            |
|                                  | [`napi_close_handle_scope`](api/v18/n-api.html#napi_close_handle_scope) |          |            |
|                                  | [`napi_open_escapable_handle_scope`](api/v18/n-api.html#napi_open_escapable_handle_scope) |          |            |
|                                  | [`napi_close_escapable_handle_scope`](api/v18/n-api.html#napi_close_escapable_handle_scope) |          |            |
|                                  | [`napi_escape_handle`](api/v18/n-api.html#napi_escape_handle) |          |            |
|                                  |                                                              |          |            |
| 对生命周期比原生方法长的值的引用 | [`napi_create_reference`](api/v18/n-api.html#napi_create_reference) |          |            |
|                                  | [`napi_delete_reference`](api/v18/n-api.html#napi_delete_reference) |          |            |
|                                  | [`napi_reference_ref`](api/v18/n-api.html#napi_reference_ref) |          |            |
|                                  | [`napi_reference_unref`](api/v18/n-api.html#napi_reference_unref) |          |            |
|                                  | [`napi_get_reference_value`](api/v18/n-api.html#napi_get_reference_value) |          |            |
|                                  |                                                              |          |            |
| 当前 ’Node‘.js 环境退出时的清理    | [`napi_add_env_cleanup_hook`](api/v18/n-api.html#napi_add_env_cleanup_hook) |          |            |
|                                  | [`napi_remove_env_cleanup_hook`](api/v18/n-api.html#napi_remove_env_cleanup_hook) |          |            |
|                                  | [`napi_add_async_cleanup_hook`](api/v18/n-api.html#napi_add_async_cleanup_hook) |          |            |
|                                  | [`napi_remove_async_cleanup_hook`](api/v18/n-api.html#napi_remove_async_cleanup_hook) |          |            |
| 在’Node‘.js环境退出时完成          |                                                              |          |            |
|                                  |                                                              |          |            |
| 模块注册                         |                                                              |          |            |
|                                  |                                                              |          |            |
| 使用JavaScript值                 |                                                              |          |            |
| 枚举类型                         | [`napi_key_collection_mode`](api/v18/n-api.html#napi_key_collection_mode) |          |            |
|                                  | [`napi_key_filter`](api/v18/n-api.html#napi_key_filter) |          |            |
|                                  | [`napi_key_conversion`](api/v18/n-api.html#napi_key_conversion) |          |            |
|                                  | [`napi_valuetype`](api/v18/n-api.html#napi_valuetype) |          |            |
|                                  | [`napi_typedarray_type`](api/v18/n-api.html#napi_typedarray_type) |          |            |
|                                  |                                                              |          |            |
| 对象创建函数                     | [`napi_create_array`](api/v18/n-api.html#napi_create_array) |          |            |
|                                  | [`napi_create_array_with_length`](api/v18/n-api.html#napi_create_array_with_length) |          |            |
|                                  | [`napi_create_arraybuffer`](api/v18/n-api.html#napi_create_arraybuffer) |          |            |
|                                  | [`napi_create_buffer`](api/v18/n-api.html#napi_create_buffer) |          |            |
|                                  | [`napi_create_buffer_copy`](api/v18/n-api.html#napi_create_buffer_copy) |          |            |
|                                  | [`napi_create_date`](api/v18/n-api.html#napi_create_date) |          |            |
|                                  | [`napi_create_external`](api/v18/n-api.html#napi_create_external) |          |            |
|                                  | [`napi_create_external_arraybuffer`](api/v18/n-api.html#napi_create_external_arraybuffer) |          |            |
|                                  | [`napi_create_external_buffer`](api/v18/n-api.html#napi_create_external_buffer) |          |            |
|                                  | [`napi_create_object`](api/v18/n-api.html#napi_create_object) |          |            |
|                                  | [`napi_create_symbol`](api/v18/n-api.html#napi_create_symbol) |          |            |
|                                  | [`node_api_symbol_for`](api/v18/n-api.html#node_api_symbol_for) |          |            |
|                                  | [`napi_create_typedarray`](api/v18/n-api.html#napi_create_typedarray) |          |            |
|                                  | [`napi_create_dataview`](api/v18/n-api.html#napi_create_dataview) |          |            |
|                                  |                                                              |          |            |
| 从 C 类型转换为 Node-API 的函数  | [`napi_create_int32`](api/v18/n-api.html#napi_create_int32) |          |            |
|                                  | [`napi_create_uint32`](api/v18/n-api.html#napi_create_uint32) |          |            |
|                                  | [`napi_create_int64`](api/v18/n-api.html#napi_create_int64) |          |            |
|                                  | [`napi_create_double`](api/v18/n-api.html#napi_create_double) |          |            |
|                                  | [`napi_create_bigint_int64`](api/v18/n-api.html#napi_create_bigint_int64) |          |            |
|                                  | [`napi_create_bigint_uint64`](api/v18/n-api.html#napi_create_bigint_uint64) |          |            |
|                                  | [`napi_create_bigint_words`](api/v18/n-api.html#napi_create_bigint_words) |          |            |
|                                  | [`napi_create_string_latin1`](api/v18/n-api.html#napi_create_string_latin1) |          |            |
|                                  | [`node_api_create_external_string_latin1`](api/v18/n-api.html#node_api_create_external_string_latin1) |          |            |
|                                  | [`napi_create_string_utf16`](api/v18/n-api.html#napi_create_string_utf16) |          |            |
|                                  | [`node_api_create_external_string_utf16`](api/v18/n-api.html#node_api_create_external_string_utf16) |          |            |
|                                  | [`napi_create_string_utf8`](api/v18/n-api.html#napi_create_string_utf8) |          |            |
|                                  |                                                              |          |            |
| 从Node-API转换为C类型的函数      | [`napi_get_array_length`](api/v18/n-api.html#napi_get_array_length) |          |            |
|                                  | [`napi_get_arraybuffer_info`](api/v18/n-api.html#napi_get_arraybuffer_info) |          |            |
|                                  | [`napi_get_buffer_info`](api/v18/n-api.html#napi_get_buffer_info) |          |            |
|                                  | [`napi_get_prototype`](api/v18/n-api.html#napi_get_prototype) |          |            |
|                                  | [`napi_get_typedarray_info`](api/v18/n-api.html#napi_get_typedarray_info) |          |            |
|                                  | [`napi_get_dataview_info`](api/v18/n-api.html#napi_get_dataview_info) |          |            |
|                                  | [`napi_get_date_value`](api/v18/n-api.html#napi_get_date_value) |          |            |
|                                  | [`napi_get_value_bool`](api/v18/n-api.html#napi_get_value_bool) |          |            |
|                                  | [`napi_get_value_double`](api/v18/n-api.html#napi_get_value_double) |          |            |
|                                  | [`napi_get_value_bigint_int64`](api/v18/n-api.html#napi_get_value_bigint_int64) |          |            |
|                                  | [`napi_get_value_bigint_uint64`](api/v18/n-api.html#napi_get_value_bigint_uint64) |          |            |
|                                  | [`napi_get_value_bigint_words`](api/v18/n-api.html#napi_get_value_bigint_words) |          |            |
|                                  | [`napi_get_value_external`](api/v18/n-api.html#napi_get_value_external) |          |            |
|                                  | [`napi_get_value_int32`](api/v18/n-api.html#napi_get_value_int32) |          |            |
|                                  | [`napi_get_value_int64`](api/v18/n-api.html#napi_get_value_int64) |          |            |
|                                  | [`napi_get_value_string_latin1`](api/v18/n-api.html#napi_get_value_string_latin1) |          |            |
|                                  | [`napi_get_value_string_utf8`](api/v18/n-api.html#napi_get_value_string_utf8) |          |            |
|                                  | [`napi_get_value_string_utf16`](api/v18/n-api.html#napi_get_value_string_utf16) |          |            |
|                                  | [`napi_get_value_uint32`](api/v18/n-api.html#napi_get_value_uint32) |          |            |
|                                  |                                                              |          |            |
| 获取全局实例的函数               | [`napi_get_boolean`](api/v18/n-api.html#napi_get_boolean) |          |            |
|                                  | [`napi_get_global`](api/v18/n-api.html#napi_get_global) |          |            |
|                                  | [`napi_get_null`](api/v18/n-api.html#napi_get_null) |          |            |
|                                  | [`napi_get_undefined`](api/v18/n-api.html#napi_get_undefined) |          |            |
|                                  |                                                              |          |            |
| 使用JavaScript值和抽象操作       | [`napi_coerce_to_bool`](api/v18/n-api.html#napi_coerce_to_bool) |          |            |
|                                  | [`napi_coerce_to_number`](api/v18/n-api.html#napi_coerce_to_number) |          |            |
|                                  | [`napi_coerce_to_object`](api/v18/n-api.html#napi_coerce_to_object) |          |            |
|                                  | [`napi_coerce_to_string`](api/v18/n-api.html#napi_coerce_to_string) |          |            |
|                                  | [`napi_typeof`](api/v18/n-api.html#napi_typeof) |          |            |
|                                  | [`napi_instanceof`](api/v18/n-api.html#napi_instanceof) |          |            |
|                                  | [`napi_is_array`](api/v18/n-api.html#napi_is_array) |          |            |
|                                  | [`napi_is_arraybuffer`](api/v18/n-api.html#napi_is_arraybuffer) |          |            |
|                                  | [`napi_is_buffer`](api/v18/n-api.html#napi_is_buffer) |          |            |
|                                  | [`napi_is_date`](api/v18/n-api.html#napi_is_date) |          |            |
|                                  | [`napi_is_error`](api/v18/n-api.html#napi_is_error_1) |          |            |
|                                  | [`napi_is_typedarray`](api/v18/n-api.html#napi_is_typedarray) |          |            |
|                                  | [`napi_is_dataview`](api/v18/n-api.html#napi_is_dataview) |          |            |
|                                  | [`napi_strict_equals`](api/v18/n-api.html#napi_strict_equals) |          |            |
|                                  | [`napi_detach_arraybuffer`](api/v18/n-api.html#napi_detach_arraybuffer) |          |            |
|                                  | [`napi_is_detached_arraybuffer`](api/v18/n-api.html#napi_is_detached_arraybuffer) |          |            |
|                                  |                                                              |          |            |
| 使用JavaScript属性               |                                                              |          |            |
| 结构                             | [`napi_property_attributes`](api/v18/n-api.html#napi_property_attributes) [`napi_property_descriptor`](api/v18/n-api.html#napi_property_descriptor) |          |            |
|                                  |                                                              |          |            |
| 函数                             | [`napi_get_property_names`](api/v18/n-api.html#napi_get_property_names) |          |            |
|                                  | [`napi_get_all_property_names`](api/v18/n-api.html#napi_get_all_property_names) |          |            |
|                                  | [`napi_set_property`](api/v18/n-api.html#napi_set_property) |          |            |
|                                  | [`napi_get_property`](api/v18/n-api.html#napi_get_property) |          |            |
|                                  | [`napi_has_property`](api/v18/n-api.html#napi_has_property) |          |            |
|                                  | [`napi_delete_property`](api/v18/n-api.html#napi_delete_property) |          |            |
|                                  | [`napi_has_own_property`](api/v18/n-api.html#napi_has_own_property) |          |            |
|                                  | [`napi_set_named_property`](api/v18/n-api.html#napi_set_named_property) |          |            |
|                                  | [`napi_get_named_property`](api/v18/n-api.html#napi_get_named_property) |          |            |
|                                  | [`napi_has_named_property`](api/v18/n-api.html#napi_has_named_property) |          |            |
|                                  | [`napi_set_element`](api/v18/n-api.html#napi_set_element) |          |            |
|                                  | [`napi_get_element`](api/v18/n-api.html#napi_get_element) |          |            |
|                                  | [`napi_has_element`](api/v18/n-api.html#napi_has_element) |          |            |
|                                  | [`napi_delete_element`](api/v18/n-api.html#napi_delete_element) |          |            |
|                                  | [`napi_define_properties`](api/v18/n-api.html#napi_define_properties) |          |            |
|                                  | [`napi_object_freeze`](api/v18/n-api.html#napi_object_freeze) |          |            |
|                                  | [`napi_object_seal`](api/v18/n-api.html#napi_object_seal) |          |            |
|                                  |                                                              |          |            |
| 使用JavaScript函数               | [`napi_call_function`](api/v18/n-api.html#napi_call_function) |          |            |
|                                  | [`napi_create_function`](api/v18/n-api.html#napi_create_function) |          |            |
|                                  | [`napi_get_cb_info`](api/v18/n-api.html#napi_get_cb_info) |          |            |
|                                  | [`napi_get_new_target`](api/v18/n-api.html#napi_get_new_target) |          |            |
|                                  | [`napi_new_instance`](api/v18/n-api.html#napi_new_instance) |          |            |
|                                  |                                                              |          |            |
| 对象封装                         | [`napi_define_class`](api/v18/n-api.html#napi_define_class) |          |            |
|                                  | [`napi_wrap`](api/v18/n-api.html#napi_wrap) |          |            |
|                                  | [`napi_unwrap`](api/v18/n-api.html#napi_unwrap) |          |            |
|                                  | [`napi_remove_wrap`](api/v18/n-api.html#napi_remove_wrap) |          |            |
|                                  | [`napi_type_tag_object`](api/v18/n-api.html#napi_type_tag_object) |          |            |
|                                  | [`napi_check_object_type_tag`](api/v18/n-api.html#napi_check_object_type_tag) |          |            |
|                                  | [`napi_add_finalizer`](api/v18/n-api.html#napi_add_finalizer) |          |            |
|                                  | [`node_api_post_finalizer`](api/v18/n-api.html#node_api_post_finalizer) |          |            |
|                                  |                                                              |          |            |
| 简单的异步操作                   | [`napi_create_async_work`](api/v18/n-api.html#napi_create_async_work) |          |            |
|                                  | [`napi_delete_async_work`](api/v18/n-api.html#napi_delete_async_work) |          |            |
|                                  | [`napi_queue_async_work`](api/v18/n-api.html#napi_queue_async_work) |          |            |
|                                  | [`napi_cancel_async_work`](api/v18/n-api.html#napi_cancel_async_work) |          |            |
|                                  |                                                              |          |            |
| 自定义异步操作                   | [`napi_async_init`](api/v18/n-api.html#napi_async_init) |          |            |
|                                  | [`napi_async_destroy`](api/v18/n-api.html#napi_async_destroy) |          |            |
|                                  | [`napi_make_callback`](api/v18/n-api.html#napi_make_callback) |          |            |
|                                  | [`napi_open_callback_scope`](api/v18/n-api.html#napi_open_callback_scope) |          |            |
|                                  | [`napi_close_callback_scope`](api/v18/n-api.html#napi_close_callback_scope) |          |            |
|                                  |                                                              |          |            |
| 版本管理                         | [`napi_get_node_version`](api/v18/n-api.html#napi_get_node_version) |          |            |
|                                  | [`napi_get_version`](api/v18/n-api.html#napi_get_version) |          |            |
|                                  |                                                              |          |            |
| 内存管理                         | [`napi_adjust_external_memory`](api/v18/n-api.html#napi_adjust_external_memory) |          |            |
|                                  |                                                              |          |            |
| Promise                          | [`napi_create_promise`](api/v18/n-api.html#napi_create_promise) |          |            |
|                                  | [`napi_resolve_deferred`](api/v18/n-api.html#napi_resolve_deferred) |          |            |
|                                  | [`napi_reject_deferred`](api/v18/n-api.html#napi_reject_deferred) |          |            |
|                                  | [`napi_is_promise`](api/v18/n-api.html#napi_is_promise) |          |            |
|                                  |                                                              |          |            |
| 脚本执行                         | [`napi_run_script`](api/v18/n-api.html#napi_run_script) |          |            |
|                                  |                                                              |          |            |
| libuv事件循环                    | [`napi_get_uv_event_loop`](api/v18/n-api.html#napi_get_uv_event_loop) |          |            |
|                                  |                                                              |          |            |
| 异步线程安全函数调用             | [调用线程安全的函数](api/v18/n-api.html#调用线程安全的函数) |          |            |
|                                  | [线程安全函数的引用计数](api/v18/n-api.html#线程安全函数的引用计数) |          |            |
|                                  | [决定是否保持进程运行](api/v18/n-api.html#决定是否保持进程运行) |          |            |
|                                  | [`napi_create_threadsafe_function`](api/v18/n-api.html#napi_create_threadsafe_function) |          |            |
|                                  | [`napi_get_threadsafe_function_context`](api/v18/n-api.html#napi_get_threadsafe_function_context) |          |            |
|                                  | [`napi_call_threadsafe_function`](api/v18/n-api.html#napi_call_threadsafe_function) |          |            |
|                                  | [`napi_acquire_threadsafe_function`](api/v18/n-api.html#napi_acquire_threadsafe_function) |          |            |
|                                  | [`napi_ref_threadsafe_function`](api/v18/n-api.html#napi_ref_threadsafe_function) |          |            |
|                                  | [`napi_unref_threadsafe_function`](api/v18/n-api.html#napi_unref_threadsafe_function) |          |            |
|                                  |                                                              |          |            |
| 使用工具                     | [`node_api_get_module_file_name`](api/v18/n-api.html#node_api_get_module_file_name) |          |            |
|                                  |                                                              |          |            |
