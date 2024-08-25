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
import ExcelJS from 'exceljs';
import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { EnumUtils } from '../utils/EnumUtils';
import { FileUtils } from '../utils/FileUtils';
import { LogUtil } from '../utils/logUtil';
import { FilesMap, Parser } from '../coreImpl/parser/parser';
import { DiffHelper } from '../coreImpl/diff/diff';
import { BasicDiffInfo, diffTypeMap, ApiDiffType } from '../typedef/diff/ApiInfoDiff';
import { WriterHelper } from './writer';
import { LocalEntry } from '../coreImpl/checker/local_entry';
import { ApiResultMessage, ApiResultSimpleInfo } from '../typedef/checker/result_type';
import { NumberConstant } from '../utils/Constant';
import { ApiStatisticsHelper } from '../coreImpl/statistics/Statistics';
import { ApiStatisticsInfo } from '../typedef/statistics/ApiStatistics';
import { SyscapProcessorHelper } from '../coreImpl/diff/syscapFieldProcessor';
import { FunctionUtils } from '../utils/FunctionUtils';

/**
 * 工具名称的枚举值，用于判断执行哪个工具
 *
 * @enum { string }
 */
export enum toolNameType {
  /**
   * 统计工具
   */
  COLLECT = 'collect',
  /**
   * 检查工具
   */
  CHECK = 'check',
  /**
   * 检查工具 线上版
   */
  CHECKONLINE = 'checkOnline',
  /**
   * diff工具
   */
  DIFF = 'diff',
  /**
   * 标签漏标检查
   */
  LABELDETECTION = 'detection',
}

/**
 * 工具名称的set集合，通过enum生成
 */
export const toolNameSet: Set<string> = new Set(EnumUtils.enum2arr(toolNameType));

/**
 * 输出文件格式,用于判断输出什么类型的文件
 *
 * @enum { string }
 */
export enum formatType {
  NULL = '',
  JSON = 'json',
  EXCEL = 'excel',
  CHANGELOG = 'changelog',
}

/**
 * 输出文件格式的set集合，通过enum生成
 */
export const formatSet: Set<string> = new Set(EnumUtils.enum2arr(formatType));

export const Plugin: PluginType = {
  pluginOptions: {
    name: 'parser',
    version: '0.1.0',
    description: 'Compare the parser the SDKS',
    commands: [
      {
        isRequiredOption: true,
        options: [`-N,--tool-name <${[...toolNameSet]}>`, 'tool name ', 'checkOnline'],
      },
      {
        isRequiredOption: false,
        options: ['-C,--collect-path <string>', 'collect api path', './api'],
      },
      {
        isRequiredOption: false,
        options: ['-F,--collect-file <string>', 'collect api file array', ''],
      },
      {
        isRequiredOption: false,
        options: ['-L,--check-labels <string>', 'detection check labels', ''],
      },
      {
        isRequiredOption: false,
        options: ['--isOH <string>', 'detection check labels', ''],
      },
      {
        isRequiredOption: false,
        options: ['--path <string>', 'check api path, split with comma', ''],
      },
      {
        isRequiredOption: false,
        options: ['--checker <string>', 'check api rule, split with comma', 'all'],
      },
      {
        isRequiredOption: false,
        options: ['--excel <string>', 'check api excel', 'false'],
      },
      {
        isRequiredOption: false,
        options: ['--old <string>', 'diff old sdk path', './api'],
      },
      {
        isRequiredOption: false,
        options: ['--new <string>', 'diff new sdk path', './api'],
      },
      {
        isRequiredOption: false,
        options: ['--old-version <string>', 'old sdk version', '0'],
      },
      {
        isRequiredOption: false,
        options: ['--new-version <string>', 'new sdk version', '0'],
      },
      {
        isRequiredOption: false,
        options: ['--output <string>', 'output file path', './'],
      },
      {
        isRequiredOption: false,
        options: [`--format <${[...formatSet]}>`, 'output file format', 'json'],
      },
      {
        isRequiredOption: false,
        options: ['--changelogUrl <string>', 'changelog url', ''],
      },
    ],
  },

  start: async function (argv: OptionObjType) {
    const toolName: toolNameType = argv.toolName;
    const method: ToolNameMethodType | undefined = toolNameMethod.get(toolName);
    if (!method) {
      LogUtil.i(
        'CommandArgs',
        `tool-name may use error name or don't have function,tool-name can use 'collect' or 'diff'`
      );
      return;
    }
    const options: OptionObjType = {
      toolName: toolName,
      collectPath: argv.collectPath,
      collectFile: argv.collectFile,
      checkLabels: argv.checkLabels,
      isOH: argv.isOH,
      path: argv.path,
      checker: argv.checker,
      old: argv.old,
      new: argv.new,
      oldVersion: argv.oldVersion,
      newVersion: argv.newVersion,
      output: argv.output,
      format: argv.format,
      changelogUrl: argv.changelogUrl,
      excel: argv.excel,
    };
    const methodInfos: ToolNameValueType = method(options);

    outputInfos(methodInfos.data, options, methodInfos.callback);
  },
  stop: function () {
    LogUtil.i('commander', `elapsed time: ${Date.now() - startTime}`);
  },
};
let startTime = Date.now();

/**
 * 工具获取完数据之后，根据format和其他数据处理输出
 *
 * @param {ToolReturnData} infos 工具返回的数据
 * @param {OptionObjType} options 传入的命令参数
 * @param {(ToolNameExcelCallback  | undefined)} callback 导出excel的回调
 */
function outputInfos(infos: ToolReturnData, options: OptionObjType, callback: ToolNameExcelCallback | undefined): void {
  const format = options.format;
  if (!format) {
    return;
  }
  switch (format) {
    case formatType.JSON:
      WriterHelper.JSONReporter(
        String(infos[0]),
        options.output,
        `${options.toolName}_${options.oldVersion}_${options.newVersion}.json`
      );
      break;
    case formatType.EXCEL:
      WriterHelper.ExcelReporter(infos, options.output, `${options.toolName}.xlsx`, callback);
      break;
    case formatType.CHANGELOG:
      WriterHelper.JSONReporter(String(infos[0]), options.output, `${options.toolName}.json`);
      break;
    default:
      break;
  }
}

/**
 * 收集api工具调用方法
 *
 * @param { OptionObjType } options
 * @return { ToolNameValueType }
 */
function collectApi(options: OptionObjType): ToolNameValueType {
  const fileDir: string = path.resolve(FileUtils.getBaseDirName(), options.collectPath);
  let collectFile: string = '';
  if (options.collectFile !== '') {
    collectFile = path.resolve(FileUtils.getBaseDirName(), options.collectFile);
  }
  let allApis: FilesMap;
  try {
    if (FileUtils.isDirectory(fileDir)) {
      allApis = Parser.parseDir(fileDir, collectFile);
    } else {
      allApis = Parser.parseFile(path.resolve(fileDir, '..'), fileDir);
    }
    const fileContent: string = Parser.getParseResults(allApis);
    if (options.format === 'excel') {
      const allApiStatisticsInfos: ApiStatisticsInfo[] | undefined =
        ApiStatisticsHelper.getApiStatisticsInfos(allApis).allApiStatisticsInfos;
      if (allApiStatisticsInfos) {
        WriterHelper.ExcelReporter(
          allApiStatisticsInfos,
          options.output,
          `all_${options.toolName}.xlsx`,
          collectApiCallback as ToolNameExcelCallback
        );
      }
    }

    return {
      data:
        options.format === 'excel'
          ? ApiStatisticsHelper.getApiStatisticsInfos(allApis).apiStatisticsInfos
          : [fileContent],
      callback: collectApiCallback as ToolNameExcelCallback,
    };
  } catch (exception) {
    const error = exception as Error;
    LogUtil.e(`error collect`, error.stack ? error.stack : error.message);
    return {
      data: [],
      callback: collectApiCallback as ToolNameExcelCallback,
    };
  }
}

function collectApiCallback(apiData: ApiStatisticsInfo[], sheet: ExcelJS.Worksheet): void {
  const apiRelationsSet: Set<string> = new Set();
  const subsystemMap: Map<string, string> = FunctionUtils.readSubsystemFile().subsystemMap;
  sheet.name = 'JsApi';
  sheet.views = [{ xSplit: 1 }];
  sheet.getRow(1).values = ['模块名', '类名', '方法名', '函数', '类型',
    '起始版本', '废弃版本', 'syscap', '错误码', '是否为系统API',
    '模型限制', '权限', '是否支持跨平台', '是否支持卡片应用', '是否为高阶API',
    '装饰器', 'kit', '文件路径', '子系统',
  ];
  let lineNumber = 2;
  apiData.forEach((apiInfo: ApiStatisticsInfo) => {
    const apiRelations: string = `${apiInfo.getHierarchicalRelations()},${apiInfo.getDefinedText()}`;
    if (apiRelationsSet.has(apiRelations)) {
      return;
    }
    sheet.getRow(lineNumber).values = [
      apiInfo.getPackageName(),
      apiInfo.getParentModuleName(),
      apiInfo.getApiName(),
      apiInfo.getDefinedText(),
      apiInfo.getApiType(),
      apiInfo.getSince() === '-1' ? '' : apiInfo.getSince(),
      apiInfo.getDeprecatedVersion() === '-1' ? '' : apiInfo.getDeprecatedVersion(),
      apiInfo.getSyscap(),
      apiInfo.getErrorCodes().join() === '-1' ? '' : apiInfo.getErrorCodes().join(),
      apiInfo.getApiLevel(),
      apiInfo.getModelLimitation(),
      apiInfo.getPermission(),
      apiInfo.getIsCrossPlatForm(),
      apiInfo.getIsForm(),
      apiInfo.getIsAutomicService(),
      apiInfo.getDecorators()?.join(),
      apiInfo.getKitInfo(),
      apiInfo.getFilePath(),
      subsystemMap.get(FunctionUtils.handleSyscap(apiInfo.getSyscap())),
    ];
    lineNumber++;
    apiRelationsSet.add(apiRelations);
  });
}
/**
 * 收集api工具调用方法
 *
 * @param { OptionObjType } options
 * @return { ToolNameValueType }
 */
function checkApi(options: OptionObjType): ToolNameValueType {
  let allApis: FilesMap;
  try {
    let fileContent: ApiResultMessage[] = [];
    if (process.env.NODE_ENV === 'development') {

      fileContent = LocalEntry.checkEntryLocal([], [], '', 'false');
    } else if (process.env.NODE_ENV === 'production') {
    }
    let finalData: (string | ApiResultMessage)[] = [];
    if (options.format === formatType.JSON) {
      finalData = [JSON.stringify(fileContent, null, NumberConstant.INDENT_SPACE)];
    } else {
      finalData = fileContent;
    }
    return {
      data: finalData,
    };
  } catch (exception) {
    const error = exception as Error;
    LogUtil.e('error check', error.stack ? error.stack : error.message);
    return {
      data: [],
    };
  }
}
/**
 * 收集api工具调用方法
 *
 * @param { OptionObjType } options
 * @return { ToolNameValueType }
 */
function checkOnline(options: OptionObjType): ToolNameValueType {
  options.format = formatType.NULL;
  try {
    LocalEntry.checkEntryLocal(options.path.split(','), options.checker.split(','), options.output, options.excel);
    return {
      data: [],
    };
  } catch (exception) {
    const error = exception as Error;
    LogUtil.e('error check', error.stack ? error.stack : error.message);
  } finally {
  }
  return {
    data: [],
  };
}

/**
 * diffApi工具调用方法
 *
 * @param { OptionObjType } options
 * @return { ToolNameValueType }
 */
function diffApi(options: OptionObjType): ToolNameValueType {
  const oldFileDir: string = path.resolve(FileUtils.getBaseDirName(), options.old);
  const newFileDir: string = path.resolve(FileUtils.getBaseDirName(), options.new);
  const status: fs.Stats = fs.statSync(oldFileDir);
  let data: BasicDiffInfo[] = [];
  try {
    if (status.isDirectory()) {
      const oldSDKApiMap: FilesMap = Parser.parseDir(oldFileDir);
      const newSDKApiMap: FilesMap = Parser.parseDir(newFileDir);
      data = DiffHelper.diffSDK(oldSDKApiMap, newSDKApiMap);
    } else {
      const oldSDKApiMap: FilesMap = Parser.parseFile(path.resolve(oldFileDir, '..'), oldFileDir);
      const newSDKApiMap: FilesMap = Parser.parseFile(path.resolve(newFileDir, '..'), newFileDir);
      data = DiffHelper.diffSDK(oldSDKApiMap, newSDKApiMap);
    }
    let finalData: (string | BasicDiffInfo)[] = [];
    if (options.format === formatType.JSON) {
      finalData = [JSON.stringify(data, null, NumberConstant.INDENT_SPACE)];
    } else {
      finalData = data;
    }
    return {
      data: finalData,
      callback: diffApiCallback as ToolNameExcelCallback,
    };
  } catch (exception) {
    const error = exception as Error;
    LogUtil.e('error diff', error.stack ? error.stack : error.message);
    return {
      data: [],
      callback: diffApiCallback as ToolNameExcelCallback,
    };
  }
}
function detectionApi(options: OptionObjType): ToolNameValueType {
  process.env.NEED_DETECTION = 'true';
  process.env.IS_OH = options.isOH;
  options.format = formatType.NULL;
  const fileDir: string = path.resolve(FileUtils.getBaseDirName(), options.collectPath);
  let collectFile: string = '';
  if (options.collectFile !== '') {
    collectFile = path.resolve(FileUtils.getBaseDirName(), options.collectFile);
  }
  let allApis: FilesMap;
  let buffer: Buffer | string = Buffer.from('');
  try {
    if (FileUtils.isDirectory(fileDir)) {
      allApis = Parser.parseDir(fileDir, collectFile);
    } else {
      allApis = Parser.parseFile(path.resolve(fileDir, '..'), fileDir);
    }
    const fileContent: string = Parser.getParseResults(allApis);
    WriterHelper.JSONReporter(
      fileContent,
      path.dirname(options.output),
      'detection.json'
    );
    let runningCommand: string = '';

    if (process.env.NODE_ENV === 'development') {
      runningCommand = `python ${path.resolve(FileUtils.getBaseDirName(), '../api_label_detection/src/main.py')} -N detection -L ${options.checkLabels} -P ${path.resolve(path.dirname(options.output), 'detection.json')} -O ${path.resolve(options.output)}`;
    } else if (process.env.NODE_ENV === 'production') {
      runningCommand = `${path.resolve(FileUtils.getBaseDirName(), './main.exe')} -N detection -L ${options.checkLabels} -P ${path.resolve(path.dirname(options.output), 'detection.json')} -O ${path.resolve(options.output)}`;
    }
    buffer = execSync(runningCommand, {
      timeout: 120000,
    });
  } catch (exception) {
    const error = exception as Error;
    LogUtil.e(`error collect`, error.stack ? error.stack : error.message);
  } finally {
    LogUtil.i(`detection run over`, buffer.toString());
  }
  return {
    data: [],
  };

}

/**
 * diffApi工具导出excel时的回调方法
 *
 * @param {BasicDiffInfo[]} data diffApi工具获取到的数据
 * @param {ExcelJS.Worksheet} sheet ExcelJS构建的Worksheet对象
 */
function diffApiCallback(data: BasicDiffInfo[], sheet: ExcelJS.Worksheet, dest?: string): void {
  sheet.name = 'api差异';
  sheet.views = [{ xSplit: 1 }];
  sheet.getRow(1).values = ['操作标记', '差异项-旧版本', '差异项-新版本', 'd.ts文件', '归属子系统', 'kit'];
  data.forEach((diffInfo: BasicDiffInfo, index: number) => {
    const dtsName = diffInfo.getNewDtsName() ? diffInfo.getNewDtsName() : diffInfo.getOldDtsName();
    sheet.getRow(index + NumberConstant.LINE_IN_EXCEL).values = [
      diffTypeMap.get(diffInfo.getDiffType()),
      joinOldMessage(diffInfo),
      joinNewMessage(diffInfo),
      dtsName.replace(/\\/g, '/'),
      SyscapProcessorHelper.matchSubsystem(diffInfo),
      SyscapProcessorHelper.getSingleKitInfo(diffInfo)

    ];
  });

  WriterHelper.MarkdownReporter.writeInMarkdown(data, dest);
}

export function joinOldMessage(diffInfo: BasicDiffInfo): string {
  if (diffInfo.getDiffMessage() === diffTypeMap.get(ApiDiffType.ADD)) {
    return 'NA';
  }
  let oldDescription: string = '';
  const relation: string[] = diffInfo.getOldHierarchicalRelations();
  const parentModuleName: string = diffInfo.getParentModuleName(relation);
  oldDescription =
    diffInfo.getOldDescription() === '-1' || !diffInfo.getOldDescription() ? 'NA' : diffInfo.getOldDescription();
  if (diffInfo.getDiffType() === ApiDiffType.KIT_CHANGE) {
    return `${oldDescription}`;
  }
  return `类名：${parentModuleName}；\n` + `API声明：${diffInfo.getOldApiDefinedText()}\n差异内容：${oldDescription}`;
}

export function joinNewMessage(diffInfo: BasicDiffInfo): string {
  if (diffInfo.getDiffMessage() === diffTypeMap.get(ApiDiffType.REDUCE)) {
    return 'NA';
  }
  let newDescription: string = '';
  const relation: string[] = diffInfo.getNewHierarchicalRelations();
  const parentModuleName: string = diffInfo.getParentModuleName(relation);
  newDescription =
    diffInfo.getNewDescription() === '-1' || !diffInfo.getNewDescription() ? 'NA' : diffInfo.getNewDescription();
  if (diffInfo.getDiffType() === ApiDiffType.KIT_CHANGE) {
    return `${newDescription}`;
  }
  return `类名：${parentModuleName}；\n` + `API声明：${diffInfo.getNewApiDefinedText()}\n差异内容：${newDescription}`;
}

/**
 * 工具名称对应执行的方法
 */
export const toolNameMethod: Map<string, ToolNameMethodType> = new Map([
  [toolNameType.COLLECT, collectApi],
  [toolNameType.CHECK, checkApi],
  [toolNameType.CHECKONLINE, checkOnline],
  [toolNameType.DIFF, diffApi],
  [toolNameType.LABELDETECTION, detectionApi],
]);

/**
 * 命令传入参数
 */
export type OptionObjType = {
  toolName: toolNameType;
  collectPath: string;
  collectFile: string;
  checkLabels: string;
  isOH: string;
  path: string;
  checker: string;
  old: string;
  new: string;
  oldVersion: string;
  newVersion: string;
  output: string;
  format: formatType;
  changelogUrl: string;
  excel: string;
};

/**
 * 各个工具当输出为excel时的回调方法
 *
 * @param { ToolReturnData } data 工具获取到的数据
 * @param { ExcelJS.Worksheet } sheet ExcelJS构建的Worksheet对象
 */
export type ToolNameExcelCallback = (data: ToolReturnData, sheet: ExcelJS.Worksheet, dest?: string) => void;

/**
 * 各个工具调用方法返回的格式
 */
export type ToolNameValueType = {
  /**
   * 工具返回的数据格式，默认为数组，方便excel输出，如果是字符串，则将字符串传入数组第一个元素
   *
   * @type { Array}
   */
  data: ToolReturnData;

  /**
   * 用于excel方法回调，返回数据以及ExcelJS构建的Worksheet对象
   *
   * @type {toolNameExcelCallback}
   */
  callback?: ToolNameExcelCallback;
};
export type ToolReturnData = (string | ApiStatisticsInfo | ApiResultMessage | BasicDiffInfo)[];

/**
 * 各个工具调用方法
 *
 */
export type ToolNameMethodType = (options: OptionObjType) => ToolNameValueType;

export type PluginType = {
  pluginOptions: PluginOptionsType;
  start: (argv: OptionObjType) => Promise<void>;
  stop: () => void;
};

export type PluginOptionsType = {
  name: string;
  version: string;
  description: string;
  commands: CommandType[];
};

export type CommandType = {
  isRequiredOption: boolean;
  readonly options: [string, string, string];
};
