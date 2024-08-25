# To-do list

## History

| 版本号 | 修订人 | 修订日期      | 修订描述 |
| ------ | ------ | ------------- | -------- |
| V0.1   | 苟晶晶 | 2024年3月25日 | 新建     |
|        |        |               |          |

## Requirement

| issue                                                        | 描述                                                         | 分析                                                         | 结论       | ToDo |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ---------- | ---- |
| 【需求】[napi_tool]:工具生成代码中增加打印调试信息           | 工具生成代码中增加关键节点信息打印，便于开发者确认流程       | 开发者通过关键信息打印，可以迅速定位问题                     | 优先级低   |      |
| 【需求】[napi_tool]: 箭头函数参数为回调函数时，编译报错      | 箭头函数的参数是箭头函数形式的回调函数时，编译报错。<br/>.d.ts文件内容如下：<br/>declare namespace napitest {<br />export class A {<br />a: string;<br />}<br />export interface InterfaceA {<br />callFunction: (result: number) => void;<br />}<br />export interface InterfaceB {<br />funcByClass: (a: A, b: number, callback: (result: number) => void, c: InterfaceA) => number;<br />}<br />// export const addByClass: (a: A, b: number, callback: (result: number) => void, c: InterfaceA) => number;<br />}<br />export default napitest; | 扩展工具的特性范围，提高工具可用性                           | 优先级低   |      |
| 【需求】[napi_tool]:（等待更佳解决方案）分离生成的工具代码普通方法和回调方法，防止嵌套使用头文件 | 需求背景： 当前工具生成的中间代码，普通方法和回调方法的接口均在一个头文件里，这样会导致嵌套使用头文件造成可读性不强，需要整改生成代码将普通方法和回调方法的接口分离到不同头文件，增加易用性和可读性<br />需求阻塞点：<br/>由于工具生成的中间代码均在 XXXmiddle.cpp 中，将XXX.h分离成XXXToC.h与XXXToJs.h之后，XXXmiddle.cpp中include<XXXToC.h>, 若.d.ts中的文件声明一个interface类中全部定义为注册回调的方法，按照预期应该将该interface声明在XXXToJs.h中，而由于注册回调的中间代码都在XXXmiddle.cpp中， XXXmiddle.cpp中该interface的构造函数用到了XXXToJs.h中定义的类，这时若要解决这个问题，就需将XXXmiddle.cpp文件进行拆分，这样代码改动太大，需寻求更佳的解决方案<br />当前进展：<br/>当前修改无法跑过test_on测试用例集 | 需求调研，提高工具可用性                                     | 优先级降低 |      |
| 【需求】[napi_tool]: on/off第二个参数支持object              | [napi_tool] on/off第二个参数支持object，其中object中定义需要注册的回调<br />function on(type: 'missionEvent', listener: MissionListener): number;<br />export interface MissionListener {<br />onMissionCreated(mission: number): void;<br />onMissionDestroyed(mission: number): void;<br />} | 扩展注册的使用场景，增加工具易用性                           | 优先级中   |      |
| 【需求】[napi_tool]: on注册回调的箭头函数支持携带js返回值给C++ | on注册回调的箭头函数支持携带js返回值给C++；<br/>1130后支持   | 需求调研，业务需要根据回调返回值进行后续处理的场景           | 优先级低   |      |
| 【需求】[napi_tool]: 支持js业务代码回调接口中的回调js函数    | function_direct处理逻辑覆盖此场景，需要增加只传递回调，不触发的场景<br />.d.ts定义：<br />function callbackWrapper(original: Function): (err: Object, value: Object) => void;<br />调用方式：<br />function callbackWrapper(original) {<br />if (typeof original !== 'function') {<br />let error = new BusinessError(`Parameter error.The type of ${original} must be function`);<br />throw error;<br />}<br />const descriptors = getOwnPropertyDescriptors(original);<br />if (typeof descriptors.length.value === 'number') {<br />descriptors.length.value++;<br />}<br />if (typeof descriptors.name.value === 'string') {<br />descriptors.name.value += 'callbackified';<br />}<br />function cb(...args) {<br />callbackified(original, ...args);<br />}<br />Object.defineProperties(cb, descriptors);<br />return cb;<br />} | 需求调研，扩展工具的特性范围，提高工具可用性。               | 优先级低   |      |
| 【需求】[napi_tool]: type, interface支持成员变量any, object, Enum为可选参数 | type, interface当前成员变量支持any, object, Enum可选参数的转换<br />当前interface/type支持可选参数类型已经包括：number, string, boolean, Array<number/boolean/string>, string/number/boolean[], Map<string/number/boolean>, {[key:string]:string/number/boolean}, number \| string \|boolean<br />待支持类型：any, object, Enum<br />.d.ts文件如下所示：<br />export enum LaunchReason {<br />UNKNOWN = 0,<br />START_ABILITY = 1,<br />CALL = 2,<br />CONTINUATION = 3,<br />}<br />type test =<br />{<br />param1?: object;<br />param2?: any;<br />param3?: Array;<br />param4?: Map<string, any>;<br />$param5?: any;<br />param6?: Array;<br />param7?: Map<string, object>;<br />param8?: LaunchReason;<br />}<br />interface interfaceTest<br />{<br />param1?: object;<br />param2?: any;<br />param3?: Array;<br />param4?: Map<string, any>;<br />$param5?: any;<br />param6?: Array;<br />param7?: Map<string, object>;<br />param8?: LaunchReason;<br />}<br />function func(v1: test, v2: interfaceTest): void; | 使用场景较少，建议暂不支持                                   | 优先级低   |      |
| 【需求】[gn, api, service, ts]:modify gn faq and add storytest for api, service, ts tools | 修改gn工具faq文档并为ts, api, service工具增加storytest，可自动化测试 | 确认需继续维护的工具可增加storytest和unittest                | 优先级中   |      |
| 【需求】[napi_tool]:ts接口定义入参/变量为any，JS调用时部分参数类型报错 | ts接口定义入参/变量为any，JS调用时参数类型为map、array、interface、interface(enum)嵌套时报错<br />ts定义如下：<br />function fun1(v: any, v1: string): number;<br />JS调用如下：<br />// map<Array<string/number/boolean>>  --当前不支持<br />ret = test.fun1({"test": ["okay", "okay"], "test1": ["res", "res"]}, 'aaa');<br />assert.strictEqual(ret, 0);<br />// Array<map<string/number/boolean>>  --当前不支持<br />ret = test.fun1([{"test": 15, "test1": 18}, {"test": 15, "test1": 18}], 'aaa');<br />assert.strictEqual(ret, 0);<br />// interface  --当前不支持<br />ret = test.fun1({'name': 'aaaa', 'age': 18}, 'aaa');<br />assert.strictEqual(ret, 0);<br />// interface<enum>  --当前不支持<br />ret = test.fun1({'type': LaunchReason.CALL, 'age': 'aaa'}, 'aaa');<br />assert.strictEqual(ret, 0); | 需求调研                                                     | 优先级低   |      |
| 【bug】[napi_tool]on回调&箭头函数回调，回调方式默认为同步，需约定异步回调方式入口 | on回调 & 箭头函数回调，回调方式默认为同步，无异步回调方式入口 | 扩展注册的使用场景，增加工具易用性，建议转需求               | 优先级中   |      |
| 【bug】[napi_tool]函数返回值支持array<map>、array<{[key:string]:any}> | 函数返回值不支持array、array<{[key:string]:any}>             | 使用场景较少，建议暂不支持                                   | 优先级低   |      |
| 【bug】[napi_tool]支持ts接口文件中namespace域的new函数       | 目前不支持ts接口文件中namespace域interface中带参数的new函数，如：new (value?: { width?: string \| number; height?: string \| number }): PolygonAttribute; | 使用场景较少，建议暂不支持                                   | 优先级低   |      |
| 【bug】[napi_tool]工具代码中若在class1中构造函数使用的class2在class1之后，生成后的代码编译报错 | 若class1中的有参构造的参数有class2时，且class2声明在class1之后，编译时报错：field ‘aPro’ has incomplete type ‘example::A’<br />.d.ts文件如下所示：<br />declare namespace example {<br />class Demo {<br />constructor(intPro: number, strPro: string, boolPro: boolean, aPro: A);<br />intPro: number;<br />strPro: string;<br />boolPro: boolean;<br />aPro: A;<br />}<br />class A<br />{<br />constructor(proA: number, proB: string, proC: boolean);<br />func1(pro: number);<br />func2(pro: string);<br />func3(pro: boolean);<br />proA: number;<br />proB: string;<br />proC: boolean;<br />}<br />} | 该bug实际是为了支持class构造函数包含class的情况，建议转需求调研 | 优先级中   |      |



## Change Log

| 计划 | 进展 | 结论 | 时间 |
| ---- | ---- | ---- | ---- |
|      |      |      |      |
|      |      |      |      |

