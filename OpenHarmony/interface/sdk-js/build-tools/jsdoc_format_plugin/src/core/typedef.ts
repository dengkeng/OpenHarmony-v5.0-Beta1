/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import ts from 'typescript';

/**
 * 流程处理结果， code值参考 constant/Code
 */
export interface ProcessResult {
  code: number,
  content: string;
}

export interface ISourceCodeProcessor {

  /**
   * 处理源码的方法，输入原始代码，输出处理后的源码。
   *
   * @param content
   */
  process(context: Context, content: string): Promise<ProcessResult>;
}

/**
 * 全局的配置选项。
 */
export class Options {
  scriptTarget: ts.ScriptTarget = ts.ScriptTarget.ES2017;

  /**
   * prettier插件配置项
   */
  formaterOption = {

    /**
     * 解析器
     */
    parser: 'typescript',

    /**
     * 单引号
     */
    singleQuote: true,

    /**
     * 代码行最大宽度
     */
    printWidth: 120,

    /**
     * 缩进的空格数
     */
    tabWidth: 2,

    /**
     * 末尾逗号 'es5'|'none'|'all'
     * es5 默认值，对象,数组末尾有. TS 中的类型参数末尾没有
     * none 没有末尾逗号
     * all 合法的位置都会出现
     */
    trailingComma: 'none',

    /**
     * {foo: bar} - false
     * { foo: bar } - true
     */
    bracketSpacing: true,

    /**
     * 表达式后的分号
     */
    semi: true,

    /**
     * 对象属性的引号
     * 'as-needed': 需要时添加
     * 'consistent': 有一个属性需要添加时,所有都添加
     * 'preserve': 保留原始
     */
    quoteProps: 'as-needed'
  };

  printerOptions = {
    omitTrailingSemicolon: false,
    removeComments: false,
    preserveSourceNewlines: true
  };

  commentOptions = {
    emptyLineUnderDescrition: true
  };
  splitUnionTypeApi: boolean = false;
  workingBranch: string = 'master';
  isTest: boolean = false;
}


/**
 * 
 * 上下文对象
 * 
 */
export interface Context {

  /**
   * 设置原始文件节点信息对象,仅供预处理时调用
   *
   * @param rawInfo
   */
  setRawSourceInfo(rawInfo: rawInfo.RawSourceCodeInfo): void;

  /**
   * 获取原始文件节点信息，用于查询原始文本位置
   */
  getRawSourceCodeInfo(): rawInfo.RawSourceCodeInfo;

  /**
   * 获取日志管理器
   */
  getLogReporter(): LogReporter;

  /**
  * 设置日志管理器
  */
  setLogReporter(logReporter: LogReporter): void;

  /**
   * 获取整改后的d.ts文件路径
   */
  getOutputFile(): string;

  /**
   * 获取待整改的d.ts文件路径
   */
  getInputFile(): string;

  /**
   * 获取d.ts AST 解析器
   *
   * @param code
   */
  getSourceParser(code: string): sourceParser.SourceCodeParser;

  /**
   * 获取全局配置对象
   */
  getOptions(): Options;
}

export namespace rawInfo {

  /**
   *  原始文件信息，包含带注释的所有AST节点信息
   */
  export abstract class RawSourceCodeInfo {
    rawCode: string;

    constructor(code: string) {
      this.rawCode = code;
    }

    abstract findRawNodeInfo(node: ts.Node): RawNodeInfo | undefined;
  }


  /**
   * 原始文件AST节点信息
   *
   */
  export interface RawNodeInfo {

    /**
     * 行号
     */
    line: number;

    /**
     * 所在行的第几个字符
     */
    character: number;

    /**
     * Ast节点对象
     */
    astNode: ts.Node;
  }

}


/**
 * 注释相关的命名空间
 */
export namespace comment {

  /**
   * 描述注释及关联的Ast节点
   */
  export interface CommentNode {
    commentInfos?: CommentInfo[];

    astNode?: ts.Node;

    parentNode?: CommentNode;
  }


  /**
   * 注释信息
   */
  export interface CommentInfo {

    /**
     * 原始注释文本
     */
    text: string;

    /**
     * 是否为多行注释
     */
    isMultiLine: boolean;

    /**
     * true为头注释，false为未注释
     */
    isLeading: boolean;

    /**
     * 注释描述
     */
    description: string;

    /**
     * 注释标签列表
     */
    commentTags: Array<CommentTag>;

    /**
     * 结构化的注释对象
     */
    parsedComment: comment.ParsedComment | undefined;

    /**
     * 注释起始位置
     */
    pos: number;

    /**
     * 注释结束位置
     */
    end: number;

    /**
     * 是否忽略此注释
     */
    ignore: boolean;

    /**
     * 是否是api注释
     */
    isApiComment: boolean,

    /**
     * 是否为特殊日志。例如，为了增加空行而添加的特殊单行日志。
     */
    isInstruct: boolean;
  }

  /**
   * 注释被拆分为以下部分:
   * |start|delimiter|postDelimiter|tag|postTag|name|postName|type|postType|description|end\
   */
  export interface CommentToken {

    /**
     * 注释每行起始字符
     */
    start: string;

    /**
     * 注释行开始定界符
     */
    delimiter: string;

    /**
     * 定界符之后的字符
     */
    postDelimiter: string;

    /**
     * 标签
     */
    tag: string;

    /**
     * 标签之后的字符
     */
    postTag: string;

    /**
     * 标签名称
     */
    name: string;

    /**
     * 标签后的字符
     */
    postName: string;

    /**
     * 类型
     */
    type: string;

    /**
     * 类型后的字符
     */
    postType: string;

    /**
     * 描述
     */
    description: string;

    /**
     * 结束字符
     */
    end: string;

    /**
     * 行结束字符
     */
    lineEnd: string;
  }

  export interface CommentSource {

    /**
     * 行号
     */
    number: number;

    /**
     * 原始注释行
     */
    source: string;

    /**
     * 注释被拆分后的对象
     */
    tokens: CommentToken;
  }


  export interface CommentTag {

    /**
     * 注释标签，例如 @param
     */
    tag: string;

    /**
     * 标签名称, 例如 @param name
     */
    name: string;

    /**
     *  类型, 例如 @param { type } name
     */
    type: string;

    /**
     * 是否可选
     */
    optional: boolean;

    /**
     * 描述
     */
    description: string;

    /**
     * 默认值
     */
    defaultValue?: string;

    /**
     * 原始注释内容
     */
    source: string;

    /**
     * 行号
     */
    lineNumber: number;

    /**
     * tag 的描述可能有多行, 首行包含tag信息，其余包含tag的描述信息。
     */
    tokenSource: Array<comment.CommentSource>;
  }

  /**
   * 未整改的d.ts文件中的注释信息。
   */
  export interface RawCommentInfo {
    start: number;
    end: number;
    comment: string;
    astNode: ts.Node
  }

  export enum CommentLocationKind {

    /**
     * 头注释
     */
    LEADING = 0,

    /**
     * 尾注释
     */
    TRAILING = 1
  }
}

/**
 * comment-parser 解析后的数据结构
 */
export namespace comment {

  /**
   *  原始注释信息
   */
  export interface Source {

    /** 行号 */
    number: number;

    /** 原始文本内容 */
    source: string;

    /** 注释拆分 */
    tokens: Token;
  }

  /**
   * 注释标签
   */
  export interface Tag {

    /**
     * 标签名如 @since tag = since
     */
    tag: string;

    /**
     * 标签名,如 @since 9, name = 9
     */
    name: string;

    /**
     * 类型, 例如 @throws { BusinessErro }, type = BusinessError
     */
    type: string;

    /**
     * 是否可选，例如 @param [encoding = 'utf-8'], optional = true
     */
    optional: boolean;

    /**
     * 标签的描述,例如 @throws { BusinessError } 401 - if the input parameters are invalid
     * description = - if the input parameters are invalid
     */
    description: string;

    /**
     * 标签对应的原始注释信息。
     */
    source: Source[];
  }

  /**
   * 注释的每行被拆分成Token的每个字段。
   */
  export interface Token {

    /**
     * 起始字符,例如本行注释的起始符号为'     ',5个空格
     */
    start: string;

    /**
     * 定界符,例如本行注释的定界符为'*'
     */
    delimiter: string;

    /**
     * 紧跟定界符之后的字符，一般为一个空格
     */
    postDelimiter: string;

    /**
     * 标签，例如 @since
     */
    tag: string;

    /**
     * 紧跟标签之后的符号, 一般是空格
     */
    postTag: string;

    /**
     * 标签名称例如 @since 9, name = 9
     * @throws { BusinessError } 401, name = 401
     */
    name: string;

    /**
     * 紧跟 name 的字符，一般为空格
     */
    postName: string;

    /**
     * 类型例如@param { string }, type = { string }
     */
    type: string;

    /**
     * 紧跟类型的字符，一般为空格
     */
    postType: string;

    /**
     * 描述信息,例如 @throws { BusinessError } 401 - if the input parameters are invalid.
     * description = - if the input parameters are invalid.
     */
    description: string;

    /**
     * 注释的结束符
     */
    end: string;

    /**
     * 行的结束符
     */
    lineEnd: string;
  }

  /**
   * comment-parser 解析后最顶层的数据结构
   */
  export interface ParsedComment {

    /**
     * 注释块中的描述信息
     */
    description: string;

    /**
     * 注释块中的标签集合
     */
    tags: Tag[];

    /**
     * 注释块的所有原始信息集合。
     */
    source: Source[];
  }
}


/**
 * 日志处理器
 */
export interface LogReporter {

  /**
   * 添加校验结果
   * 
   * @param checkResult 校验结果对象
   */
  addCheckResult(checkResult: CheckLogResult): void

  /**
   * 添加整改结果
   * 
   * @param modifyResult 整改结果对象
   */
  addModifyResult(modifyResult: ModifyLogResult): void

  /**
   * 获取校验结果映射表
   */
  getCheckResultMap(): Map<string, string>;

  /**
   * 获取整改结果映射表
   */
  getModifyResultMap(): Map<string, string>;

  /**
   * 将校验结果报告落盘
   * @param path 报告落盘路径
   */
  writeCheckResults(path: string): Promise<void>;

  /**
   * 将整改结果报告落盘
   * @param path 报告落盘路径
   */
  writeModifyResults(path: string): Promise<void>;

  /**
   * 将结果报告落盘
   * @param path 报告落盘路径
   */
  writeAllResults(path: string): Promise<void>;

  /**
   * 传入writer对象
   * 
   * @param writer writer对象
   */
  setWriter(writer: LogWriter): void;
}

/**
 * 校验结果对象定义
 * 
 * TODO
 */
export interface CheckLogResult {
  // 文件地址（行号，列号）
  filePath?: string;
  // 接口名称
  apiName: string;
  // 接口内容
  apiContent?: string;
  // 异常类型
  errorType: string;
  // 告警信息
  errorInfo: string;
  // 版本号
  version: string;
  // 模块名称
  moduleName: string;
}

/**
 * 整改结果对象定义
 * 
 * TODO
 */
export interface ModifyLogResult {
  // 文件地址（行号，列号）
  filePath?: string;
  // 接口名称
  apiName?: string;
  // 接口内容
  apiContent?: string;
  // 整改类型
  modifyType: string;
  // 版本号
  version: string;
  // 描述
  description: string;
  // 模块名称
  moduleName?: string;
}

/**
 * 结果日志输出接口
 */
export interface LogWriter {

  /**
   * 
   * @param checkResults 校验结果集
   * @param modifyResults 整改结果集
   * @param path 报告落盘路径
   */
  writeResults(checkResults: Array<CheckLogResult> | undefined, modifyResults: Array<ModifyLogResult> | undefined, path: string): Promise<void>;
}

/**
 * JSDoc整改类型枚举类
 */
export enum JSDocModifyType {
  EVENT_SUBSCRIPTION_SPLITTION = '事件订阅api拆分',
  AYYNCHRONOUS_FUNCTION_JSDOC_COPY = '同名异步函数共用JSDoc拆分',
  MISSING_TAG_COMPLETION = '缺失标签补全',
  TAG_ORDER_AJUSTMENT = '标签顺序调整'
}

/**
 * JSDoc校验异常类型枚举类
 */
export enum JSDocCheckErrorType {
  INCOMPLETE_TAG = '无法补全的标签',
  API_FORMAT_ERROR = 'api格式错误',
  TAG_VALUE_ERROR = '标签使用错误',
  PARAM_DESCRIPTION_WARNING = '缺失param标签描述信息'
}

export namespace sourceParser {

  /**
   * 源码解析器
   */
  export abstract class SourceCodeParser {
    content: string;
    constructor(sourceCode: string) {
      this.content = sourceCode;
    }

    /**
     * 节点树修改方法，新节点通过 {@code ITransformCallback#onTransformNode} 返回
     * 
     * @param callback
     */
    abstract transform(callback: ITransformCallback): ts.SourceFile | undefined;

    /**
     * 遍历所有待注释的节点，解析对应注释并调用 INodeVisitorCallback#onVisitNode
     * 用于校验、注释整改。
     * 
     * @param callback
     */
    abstract visitEachNodeComment(callback: INodeVisitorCallback, onlyVisitHasComment?: boolean): ts.SourceFile | undefined;

    /**
     * 打印源代码
     * 
     * @param sourceFile
     */
    abstract printSourceFile(sourceFile: ts.SourceFile): string;

    /**
     * 创建ts.SourceFile对象。对于非TS代码文件也可以被解析成改对象。
     *
     * @param content 文件内容
     * @param name 文件名
     */
    abstract createSourceFile(content: string, name?: string): ts.SourceFile | undefined;
  }

  /**
   * AST 节点修改回调接口
   */
  export interface ITransformCallback {

    /**
     * 入参为原始AST节点，自定义业务功能，并返回新的AST节点。
     *
     * @param node 新的节点对象，若不创建新节点则返回undefined
     */
    onTransformNode(node: comment.CommentNode): ts.Node | undefined;
  }


  /**
   * 节点遍历回调接口
   */
  export interface INodeVisitorCallback {
    onVisitNode(node: comment.CommentNode): void;
  }
}

/**
 * 整改工具的API
 */
export interface IJSDocModifier {
  start(): Promise<void>;
}

interface OrderResultInfo {
  checkResult: boolean;
  errorInfo: string;
}

export interface IllegalTagsInfo {
  checkResult: boolean;
  errorInfo: string;
  index: number;
}

/**
 * 单个节点检查返回格式
 */
export interface JsDocCheckResult {
  orderResult: OrderResultInfo;
  illegalTags: IllegalTagsInfo[];
  missingTags: string[];
}

export interface JsDocModificationInterface {
  (node: comment.CommentNode, commentInfo: comment.CommentInfo, tagName: string, context: Context | undefined): boolean;
}

/**
 * 错误告警
 */
export enum ErrorInfo {
  PARAM_FORAMT_ERROR = '@param标签无法补全, 请自行确认当前api第[$$]个参数是否为基础类型或定义类型.',
  PARAM_FORAMT_DESCRIPTION_ERROR = '请自行添加第[$$]个参数的描述信息.',
  COMPLETE_TAG_INFORMATION = '补全第[$$]段JSDoc的@$$标签.',
  COMPLETE_INHERIT_TAG_INFORMATION = '第[$$]段JSDoc从父类继承@$$标签.',
  COMPLETE_INHERIT_PERMISSION_TAG_ERROR = '第[$$]段JSDoc父类存在@$$标签, 请自行确认并补全相同标签.',
  COMPLETE_TAG_ERROR = '第[$$]段JSDoc缺少@$$标签, 请自行确认并修改.',
  COMPLETE_INTERFACE_TAG_ERROR = '第[$$]段JSDoc缺少@interface或@typedef标签, 请自行确认并补全@interface或@typedef标签.',
  MODIFY_TAG_ORDER_INFORMATION = '第[$$]段JSDoc标签顺序调整.',
  JSDOC_FORMAT_ERROR = 'JSDoc格式错误, 请检查.',
  JSDOC_ILLEGAL_ERROR = '第[$$]段JSDoc校验失败: \n',
  EVENT_SUBSCRIPTION_SPLITTION = '对事件订阅函数[$$]进行了拆分.',
  AYYNCHRONOUS_FUNCTION_JSDOC_COPY = '对异步函数[$$]进行了JSDoc复制.'
}

/**
 * 方法或函数节点联合类型定义
 */
export type MethodNodeType = ts.FunctionDeclaration | ts.MethodDeclaration | ts.MethodSignature;

export interface ApiSplitProcessorInterface {
  (node: ts.Node, context: Context | undefined): ts.Node | undefined;
}

/**
   * 注释信息
   */
export interface CommentData {
  tag: string,
  name: string,
  type: string,
  optional: boolean,
  description: string,
  source: Array<comment.CommentSource>,
  default: string
}