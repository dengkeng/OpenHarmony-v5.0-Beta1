# 将三方库集成到OpenHarmony的方法

## 场景说明

为了实现移植的三方库被其它子系统或者应用调用，将需移植的三方库Cmake或make编译方式转换为BUILD.gn编译方式之后，需要将其源码编译集成到OpenHarmony系统中，使其生成动态库，供OpenHarmony应用层调用。本文介绍如何将需移植的三方库源码利用OpenHarmony编译系统生成动态库供应用层调用。

## 修改生成的BUILD.gn文件(有-a参数时)

1、若待转换三方库中需要引用其它三方库时，需要填写-a参数，具体填写方法可参考FAQ中三方库转换时问题解决方法，详细FAQ内容可左键单击以下链接了解：[FAQ](https://gitee.com/openharmony/napi_generator/blob/master/hdc/gn/FAQ.md)；在build_tmp下生成的BUILD.gn中，需要修改deps依赖，根据-a参数中填写的依赖在OpenHarmony源码third_party下所有BUILD.gn中查找依赖的库的定义，然后复制库的路径，在生成的BUILD.gn文件中的deps中修改依赖的库的路径。例如：转换curl三方库时依赖ssl和crypto库：

-a参数中包含的依赖：

```
(-DOPENSSL_INCLUDE_DIR=/home/kaihong1/Openharmony1207/third_party/boringssl/src/include,-DOPENSSL_CRYPTO_LIBRARY=/home/kaihong1/Openharmony1207/out/hi3516dv300/developtools/profiler/libcrypto.z.so,-DOPENSSL_SSL_LIBRARY=/home/kaihong1/Openharmony1207/out/hi3516dv300/developtools/profiler/libssl.z.so)
```

生成的BUILD.gn文件（build_tmp/lib/BUILD.gn）：

```
 ...
 deps = [
        "//out/hi3516dv300/developtools/profiler/libssl.z.so",
        "//out/hi3516dv300/developtools/profiler/libcrypto.z.so"
    ]
 ...
```

修改为：

```
 ...
 deps = [
         "//third_party/boringssl:ssl",
         "//third_party/boringssl:crypto"
    ]
 ...
```

同理修改build_tmp/src下的BUILD.gn文件。

## 通过其它子系统调用

1、此处以OpenHarmony/foundation/multimodalinput组件调用mbedtls-development组件为例。在~/multimodalinput/input/BUILD.gn文件中添加mbedtls-development依赖，其中“//third_party/mbedtls-development/build_tmp”为mbedtls-development组件BUILD.gn文件所在相对路径；“all_targets”为mbedtls-development组件BUILD.gn文件中group名称。具体书写如下所示：

```
harmony@Ubuntu-64:~$ cd /home/harmony/OpenHarmony/foundation/multimodalinput/input/
	harmony@Ubuntu-64:~/OpenHarmony/foundation/multimodalinput/input$ cat BUILD.gn 
	......
	ohos_shared_library("mmi_uinject") {
	......
  	  deps = [
    	"//drivers/peripheral/input/hal:hdi_input",
    	"//utils/native/base:utils",
    	"//third_party/mbedtls-development/build_tmp:all_targets",
  	  ]
	......
```

2、进入~/OpenHarmony目录下，通过ninja形式编译，编译命令及编译结果如下：

```
ninja -C out/khdvk_rk3568_a all_targets
```

![](C:\napi_generator_aboutTest\gjj_servicetest_230220\napi_generator_gou\hdc\gn\figures\ninja_build_success.png)

3、编译成功后，会生成mbedtls-development相关动态库文件或可执行程序，生成文件及路径如下所示：

![](C:\napi_generator_aboutTest\gjj_servicetest_230220\napi_generator_gou\hdc\gn\figures\generate_file.png)

## 总结

根据以上操作，即可将三方库集成到OpenHarmony源码中。
