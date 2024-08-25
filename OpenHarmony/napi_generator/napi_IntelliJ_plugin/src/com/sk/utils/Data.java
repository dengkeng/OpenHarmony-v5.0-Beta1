/*
 * Copyright (c) 2023 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.sk.utils;

/**
 * 配置信息类，提供自定义的配置信息类
 *
 * @author: goujingjing
 * @see: generator dialog
 * @version: v1.0.3
 * @since 2023-12-14
 */
public class Data {
    private String genPath;
    private String includeName;
    private String cppName;
    private String interfaceName;
    private String serviceCode;

    /**
     * 构造函数
     *
     * @param genPath   用户配置的生成框架路径
     * @param includeName   用户配置的业务代码头文件相对路径
     * @param cppName       用户配置的业务代码cpp文件相对路径
     * @param interfaceName 用户配置的业务代码接口名
     * @param serviceCode   用户配置的调用业务代码的代码
     * @throws log 输出异常
     */
    public Data(String genPath, String includeName, String cppName, String interfaceName,
                String serviceCode) {
        this.genPath = genPath;
        this.includeName = includeName;
        this.cppName = cppName;
        this.interfaceName = interfaceName;
        this.serviceCode = serviceCode;
    }

    /**
     * get函数
     * @param void 空
     * @return 用户配置的业务代码根路径
     * @throws log 输出异常
     */
    public String getGenPath() {
        return genPath;
    }

    /**
     * set函数
     *
     * @param genPath   用户配置的业务代码根路径
     * @throws log 输出异常
     */
    public void setGenPath(String genPath) {
        this.genPath = genPath;
    }

    /**
     * get函数
     * @param void 空
     * @return 用户配置的业务代码头文件相对路径
     * @throws log 输出异常
     */
    public String getIncludeName() {
        return includeName;
    }

    /**
     * set函数
     * @param includeName 用户配置的业务代码头文件相对路径
     * @throws log 输出异常
     */
    public void setIncludeName(String includeName) {
        this.includeName = includeName;
    }

    /**
     * get函数
     * @param void 空
     * @return 用户配置的业务代码cpp文件相对路径
     * @throws log 输出异常
     */
    public String getCppName() {
        return cppName;
    }

    /**
     * set函数
     * @param cppName 用户配置的业务代码cpp文件相对路径
     * @throws log 输出异常
     */
    public void setCppName(String cppName) {
        this.cppName = cppName;
    }

    /**
     * get函数
     * @param void 空
     * @return 用户配置的业务代码接口名
     * @throws log 输出异常
     */
    public String getInterfaceName() {
        return interfaceName;
    }

    /**
     * set函数
     * @param interfaceName 用户配置的业务代码接口名
     * @throws log 输出异常
     */
    public void setInterfaceName(String interfaceName) {
        this.interfaceName = interfaceName;
    }

    /**
     * get函数
     * @param void 空
     * @return 用户配置的调用业务代码的代码
     * @throws log 输出异常
     */
    public String getServiceCode() {
        return serviceCode;
    }

    /**
     * set函数
     * @param serviceCode 用户配置的调用业务代码的代码
     * @throws log 输出异常
     */
    public void setServiceCode(String serviceCode) {
        this.serviceCode = serviceCode;
    }
}
