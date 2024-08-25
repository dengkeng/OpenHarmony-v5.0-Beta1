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

export namespace Comment {
  export enum JsDocTag {
    SYSCAP = 'syscap',
    SINCE = 'since',
    FORM = 'form',
    CROSS_PLAT_FORM = 'crossplatform',
    SYSTEM_API = 'systemapi',
    STAGE_MODEL_ONLY = 'stagemodelonly',
    FA_MODEL_ONLY = 'famodelonly',
    DEPRECATED = 'deprecated',
    USEINSTEAD = 'useinstead',
    TYPE = 'type',
    CONSTANT = 'constant',
    PERMISSION = 'permission',
    THROWS = 'throws',
    ATOMIC_SERVICE = 'atomicservice',
    KIT = 'kit',
    FILE = 'file',
  }

  export interface JsDocProcessorInterface {
    (jsDocInfo: JsDocInfo, commentTag: Comment.CommentTag): void;
  }

  export class JsDocInfo {
    description: string = ''; // jsdoc的整体描述
    syscap: string = ''; // @syscap标签--api的系统能力
    since: string = '-1'; // @since标签--api的起始版本
    isForm: boolean = false; // @form标签--api是否支持卡片应用
    isCrossPlatForm: boolean = false; // @crossplatform标签--api是否支持跨平台
    isSystemApi: boolean = false; // @systemapi--api是否是系统api
    modelLimitation: string = ''; // @stagemodelonly或@famodelonly--api的使用模型限制
    deprecatedVersion: string = '-1'; // @deprecated标签--api的废弃版本
    useinstead: string = ''; // @useinstead标签--api的替换接口
    permissions: string = ''; // @permission标签--api的权限
    errorCodes: number[] = []; // @throws标签--api的错误码
    typeInfo: string = ''; // @type标签--标注的类型信息
    isConstant: boolean = false; // @constant标签--标注api为常量
    isAtomicService: boolean = false; //@atomicservice--标注是否为高阶API
    kit: string = '';
    isFile: boolean = false;
    tags: CommentTag[] | undefined = undefined;

    constructor() {}

    setDescription(description: string): JsDocInfo {
      this.description = description;
      return this;
    }

    getDescription(): string {
      return this.description;
    }

    setSyscap(syscap?: string): JsDocInfo {
      if (syscap) {
        this.syscap = syscap;
      }
      return this;
    }

    getSyscap(): string {
      return this.syscap;
    }

    setSince(since: string): JsDocInfo {
      this.since = since;
      return this;
    }

    getSince(): string {
      return this.since;
    }

    setIsForm(isForm: boolean): JsDocInfo {
      this.isForm = isForm;
      return this;
    }

    getIsForm(): boolean {
      return this.isForm;
    }

    setIsCrossPlatForm(isCrossPlatForm: boolean): JsDocInfo {
      this.isCrossPlatForm = isCrossPlatForm;
      return this;
    }

    getIsCrossPlatForm(): boolean {
      return this.isCrossPlatForm;
    }

    setIsSystemApi(isSystemApi: boolean): JsDocInfo {
      this.isSystemApi = isSystemApi;
      return this;
    }

    getIsSystemApi(): boolean {
      return this.isSystemApi;
    }

    setIsAtomicService(isAtomicService: boolean): JsDocInfo {
      this.isAtomicService = isAtomicService;
      return this;
    }

    getIsAtomicService(): boolean {
      return this.isAtomicService;
    }

    setModelLimitation(modelLimitation: string): JsDocInfo {
      this.modelLimitation = modelLimitation;
      return this;
    }

    getModelLimitation(): string {
      return this.modelLimitation;
    }

    setDeprecatedVersion(deprecatedVersion: string): JsDocInfo {
      this.deprecatedVersion = deprecatedVersion;
      return this;
    }

    getDeprecatedVersion(): string {
      return this.deprecatedVersion;
    }

    setUseinstead(useinstead: string): JsDocInfo {
      this.useinstead = useinstead;
      return this;
    }

    getUseinstead(): string {
      return this.useinstead;
    }

    setPermission(permissions: string): JsDocInfo {
      this.permissions = permissions;
      return this;
    }

    getPermission(): string {
      return this.permissions;
    }

    addErrorCode(errorCode: number): JsDocInfo {
      this.errorCodes.push(errorCode);
      return this;
    }

    getErrorCode(): number[] {
      return this.errorCodes;
    }

    setTypeInfo(typeInfo: string): JsDocInfo {
      this.typeInfo = typeInfo;
      return this;
    }

    getTypeInfo(): string {
      return this.typeInfo;
    }

    setIsConstant(isConstant: boolean): JsDocInfo {
      this.isConstant = isConstant;
      return this;
    }

    getIsConstant(): boolean {
      return this.isConstant;
    }

    setKit(kit: string): JsDocInfo {
      this.kit = kit;
      return this;
    }

    getKit(): string {
      return this.kit;
    }

    setIsFile(isFile: boolean): JsDocInfo {
      this.isFile = isFile;
      return this;
    }

    getIsFile(): boolean {
      return this.isFile;
    }

    setTags(tags: CommentTag[]): JsDocInfo {
      this.tags = tags;
      return this;
    }

    removeTags(): JsDocInfo {
      this.tags = undefined;
      return this;
    }

    addTag(tag: CommentTag): JsDocInfo {
      if (!this.tags) {
        this.tags = [];
      }
      this.tags.push(tag);
      return this;
    }

    getTags(): CommentTag[] | undefined {
      return this.tags;
    }
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
    parsedComment: any;

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
    isApiComment: boolean;

    /**
     * 是否为特殊日志。例如，为了增加空行而添加的特殊单行日志。
     */
    isInstruct: boolean;

    /**
     * 是否为文件的jsdoc
     */
    isFileJsDoc: boolean;
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
    tokenSource: Array<Comment.CommentSource>;
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
}
