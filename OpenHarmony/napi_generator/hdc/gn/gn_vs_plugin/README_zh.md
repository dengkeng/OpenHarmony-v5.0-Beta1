# GN脚本生成工具VS code插件说明

## 简介

GN脚本生成工具，它可以根据用户给定三方库项目的CMakeLists.txt文件，转换生成BUILD.gn文件。目前工具支持可执行文件、VS Code插件两种入口，本文主要介绍VS Code插件使用说明。

## 目录 

	├── gn                            # GN脚本生成工具
	│   ├── ...                       # 其他文件
	│   ├── gn_vs_plugin              # VS Code插件代码
	│   │   ├── docs                  # VS Code插件说明
	│   │   ├── src    				  # VS Code插件源码
	│   │   └── README_zh             # VS Code插件说明

## 约束 

系统：不限

依赖版本：JDK 11

开发工具：DevEco stdio、IDEA Community 2021.3.3

## 使用方法 

### 使用对象

系统开发者

### 使用场景

1)移植CMakeLists.txt编译方式的三方库到OpenHarmony源码中。

### 工具使用

插件下载路径如下:

[下载链接](http://ftpkaihongdigi.i234.me:5000/fsdownload/1OjtRhtGf/gn-gen-0.0.1)

具体的工具使用步骤，可以左键单击以下链接了解：

[工具使用说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/gn/gn_vs_plugin/docs/INSTRUCTION_ZH.md)

### 工具输出

根据使用者指定三方库的CMakeLists.txt文件，工具会输出对应的BUILD.gn文件。为了方便使用者快速上手工具，可供测试的三方库项目目录如下：

	harmony@Ubuntu-64:~/OpenHarmony/third_party/mbedtls-development$ ls
	3rdparty  BUGS.md  ChangeLog  cmake  configs  DartConfiguration.tcl  docs  include  LICENSE  programs  scripts  SUPPORT.md  visualc  BRANCHES.md  ChangeLog.d  CMakeLists.txt  CONTRIBUTING.md  dco.txt  doxygen  library  Makefile  README.md  SECURITY.md  tests

在linux环境下的，根据输入三方库项目的CMakeLists.txt文件,生成的输出文件，如下所示：

	harmony@Ubuntu-64:~/OpenHarmony/third_party/mbedtls-development$ ls
	3rdparty  BUGS.md  ChangeLog  cmake  configs  DartConfiguration.tcl  docs  include  LICENSE  programs  scripts  SUPPORT.md  visualc  BRANCHES.md  build_tmp  ChangeLog.d  CMakeLists.txt  CONTRIBUTING.md  dco.txt  doxygen  library  Makefile  README.md  SECURITY.md  tests
	harmony@Ubuntu-64:~/OpenHarmony/third_party/mbedtls-development$ cd build_tmp/
	harmony@Ubuntu-64:~/OpenHarmony/third_party/mbedtls-development/build_tmp$ ls
	3rdparty  BUILD.gn  cmake  CMakeCache.txt  CMakeFiles  cmake_install.cmake  CTestTestfile.cmake  DartConfiguration.tcl  include  library  Makefile  ohos.toolchain.cmake  programs  scripts  tests

其中生成的BUILD.gn文件，内容如下所示：

```
import("//build/ohos.gni")

group("all_targets") {
    deps = [
        #静态库
        "//third_party/mbedtls-development/build_tmp/library:mbedcrypto",
        "//third_party/mbedtls-development/build_tmp/library:mbedx509",
        "//third_party/mbedtls-development/build_tmp/library:mbedtls",

        #可执行程序
        "//third_party/mbedtls-development/build_tmp/programs/aes:crypt_and_hash",
        "//third_party/mbedtls-development/build_tmp/programs/cipher:cipher_aead_demo",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_x509crl",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_x509csr",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_pubkey",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_pkcs7",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_privkey",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_client",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_dtlsserver",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_dtlsclient",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_x509crt",
        "//third_party/mbedtls-development/build_tmp/programs/fuzz:fuzz_server",
        "//third_party/mbedtls-development/build_tmp/programs/hash:generic_sum",
        "//third_party/mbedtls-development/build_tmp/programs/hash:hello",
        "//third_party/mbedtls-development/build_tmp/programs/hash:md_hmac_demo",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:mpi_demo",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:key_app",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:pk_encrypt",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:gen_key",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:ecdsa",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:rsa_encrypt",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:dh_client",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:dh_server",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:dh_genprime",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:ecdh_curve25519",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:pk_decrypt",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:pk_sign",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:key_app_writer",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:pk_verify",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:rsa_decrypt",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:rsa_genkey",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:rsa_sign",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:rsa_sign_pss",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:rsa_verify",
        "//third_party/mbedtls-development/build_tmp/programs/pkey:rsa_verify_pss",
        "//third_party/mbedtls-development/build_tmp/programs/psa:key_ladder_demo",
        "//third_party/mbedtls-development/build_tmp/programs/psa:crypto_examples",
        "//third_party/mbedtls-development/build_tmp/programs/psa:aead_demo",
        "//third_party/mbedtls-development/build_tmp/programs/psa:hmac_demo",
        "//third_party/mbedtls-development/build_tmp/programs/psa:psa_constant_names",
        "//third_party/mbedtls-development/build_tmp/programs/random:gen_entropy",
        "//third_party/mbedtls-development/build_tmp/programs/random:gen_random_ctr_drbg",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:ssl_pthread_server",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:ssl_client1",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:ssl_client2",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:mini_client",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:dtls_server",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:dtls_client",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:ssl_server",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:ssl_server2",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:ssl_context_info",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:ssl_fork_server",
        "//third_party/mbedtls-development/build_tmp/programs/ssl:ssl_mail_client",
        "//third_party/mbedtls-development/build_tmp/programs/test:selftest",
        "//third_party/mbedtls-development/build_tmp/programs/test:benchmark",
        "//third_party/mbedtls-development/build_tmp/programs/test:udp_proxy",
        "//third_party/mbedtls-development/build_tmp/programs/test:query_compile_time_config",
        "//third_party/mbedtls-development/build_tmp/programs/test:zeroize",
        "//third_party/mbedtls-development/build_tmp/programs/util:pem2der",
        "//third_party/mbedtls-development/build_tmp/programs/util:strerror",
        "//third_party/mbedtls-development/build_tmp/programs/x509:load_roots",
        "//third_party/mbedtls-development/build_tmp/programs/x509:cert_req",
        "//third_party/mbedtls-development/build_tmp/programs/x509:cert_write",
        "//third_party/mbedtls-development/build_tmp/programs/x509:crl_app",
        "//third_party/mbedtls-development/build_tmp/programs/x509:req_app",
        "//third_party/mbedtls-development/build_tmp/programs/x509:cert_app",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_x509write",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_x509parse",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_its",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_storage_format.current",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_timing",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_ssl",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_rsa",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_entropy",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_shax",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_hmac_drbg.pr",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_dhm",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_ecdsa",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.des",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_poly1305",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_ctr_drbg",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.null",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.gcm",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_storage_format.misc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_ccm",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.camellia",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_chachapoly",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_mdx",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_des",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.chacha20",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_bignum.generated",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_bignum_mod",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_chacha20",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_aria",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_not_supported.generated",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.padding",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.nist_kw",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_aes.ofb",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_hmac_drbg.nopr",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_aes.ecb",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_hkdf",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_aes.cfb",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.ccm",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_pkcs5",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.aes",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_bignum.misc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_aes.rest",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cmac",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_camellia",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_ecdh",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_md",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.chachapoly",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_storage_format.v0",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_asn1parse",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_asn1write",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_base64",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_bignum_mod_raw.generated",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_oid",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.misc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_bignum_core.misc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_ecjpake",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_bignum_core.generated",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_bignum_mod_raw",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_random",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_aes.cbc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_pk",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_version",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_se_driver_hal_mocks",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_bignum_mod.generated",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_debug",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_pkcs1_v21",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_gcm.aes128_de",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_cipher.aria",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_gcm.aes128_en",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_gcm.aes192_de",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_gcm.camellia",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_gcm.aes192_en",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_gcm.aes256_de",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_gcm.aes256_en",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_gcm.misc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_hmac_drbg.misc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_hmac_drbg.no_reseed",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_lms",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_mps",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_memory_buffer_alloc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_net",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_nist_kw",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_metadata",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_pkparse",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_hash",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_pem",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_pkcs12",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_attributes",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_aes.xts",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_op_fail.generated",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_pkcs1_v15",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_pkcs7",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_pkwrite",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_not_supported.misc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_driver_wrappers",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_entropy",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_generate_key.generated",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_init",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_op_fail.misc",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_error",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_pake",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_lmots",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_persistent_key",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_se_driver_hal",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_ecp",
        "//third_party/mbedtls-development/build_tmp/tests:test_suite_psa_crypto_slot_management",

    ]
}
```



## 开发说明

### 对象

工具的开发者

### 开发场景

若当前工具的功能已经不能满足开发者的全部需求，则开发者可以基于已有的源码对工具进行二次开发，来增强工具的能力，编译打包生成自定义的可执行文件和插件。  
### 开发步骤

开发者可以根据如下的步骤来完成对工具VSCode插件的开发：

[工具开发说明](https://gitee.com/openharmony/napi_generator/tree/master/hdc/gn/gn_vs_plugin/docs/DEVELOP_ZH.md)

## FAQ

对于常见问题解决方法指导如下：

[FAQ](https://gitee.com/openharmony/napi_generator/tree/master/hdc/gn/FAQ.md)

## 相关仓

暂无