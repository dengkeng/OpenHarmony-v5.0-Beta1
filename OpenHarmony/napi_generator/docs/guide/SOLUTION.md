# 当前已知不支持推荐方案

1.注册的object回调不支持箭头函数写法,  注册回调格式为addXXX，注销回调格式为removeXXX，且回调方法命名格式为onXXX, 例如:

```
export interface InterfaceB {
    byClass: (listener: InterfaceA) => void;
}
export interface InterfaceA {
    callFunction: (res: number) => void;
}
```

修改为:

```
export interface InterfaceB {
    // object注册回调, 关键字：add
    addByClass(listener: InterfaceA);
    // object注销回调, 关键字：remove
    removeByClass(listener: InterfaceA);
}
export interface InterfaceA {
    onCallFunction(res: number): void;
}
```

2.注册回调只能支持单个参数, 且注册单个参数的注册回调方法命名格式为registerXXX, 例如:

```
export interface TestA {
    bGyClass: (a: number, callback: (result: number) => void) => number;
}
```

修改为:

```
export interface TestA {
    // 原bGyClass的参数 callback: (res: number) => void 改为registerXXX/unRegisterXXX形式
    // register形式注册回调， 关键字：register
    registerTestACallback(callback: (dd: number) => void); 
    // unRegister形式注销回调, 关键字：unRegister
    unRegisterTestACallback(callback: (dd: number) => void); 
    // gByClass用于调用回调
    bGyClass: (a: number) => number;
}
```

3.生成报错：The current version does not support generating parameter。

```
genError:at paramGenerate [C:\snapshot\napi_generator\src\gen\generate\param_generate.js(899:17)] The current version does not support generating parameter [elementName] with type [ElementName]
```

ts文件为：

```
import { ElementName } from './bundleManager/ElementName';

declare namespace cardEmulation {
  export class HceService {
    start(elementName: ElementName, aidList: string[]): void;
    stop(elementName: ElementName): void;
  }
}
export default cardEmulation;
```

修改：

文件中引用了 ElementName 类型， 需要把被引用的文件( import { ElementName } from './bundleManager/ElementName'; ）放到转换路径下工具才可进行转换