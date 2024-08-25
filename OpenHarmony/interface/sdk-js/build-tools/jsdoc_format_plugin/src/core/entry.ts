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

import { Code, ConstantValue, StringResourceId } from '../utils/constant';
import { FileUtils } from '../utils/fileUtils';
import { LogLevelUtil, LogUtil } from '../utils/logUtil';
import { StringUtils, StringResource } from '../utils/stringUtils';
import { ApiSplitProcessor } from './apiSplitProcessor';
import { AsynchronousFunctionProcessor } from './asynchronousFunctionProcessor';
import { ContextImpl, InputParameter, OutputFileHelper } from './coreImpls';
import { CommentModificationProcessor } from './modificationProcessor';
import { OutputProcessor } from './outputProcessor';
import { RawSourceCodeProcessor } from './rawCodeProcessor';
import type { Context, IJSDocModifier, ISourceCodeProcessor, LogReporter, ProcessResult } from './typedef';

/**
 * JSDoc 整改流程入口。
 */
export class JSDocModifierImpl implements IJSDocModifier {
  tag: string = 'jsdoc-tool';
  async start(): Promise<void> {
    await this.startInternal();
  }

  async startInternal(): Promise<void> {
    try {
      const inputParameter = new InputParameter();
      inputParameter.parse();
      LogUtil.logLevel = LogLevelUtil.get(inputParameter.logLevel);
      const sourceProcessor: ISourceCodeProcessor = this.getSourceProcessor(inputParameter);
      const baseContext: Context = this.getBaseContext(inputParameter);
      LogUtil.i(this.tag, StringResource.getString(StringResourceId.START_MESSAGE));
      const result: ProcessResult = await sourceProcessor.process(baseContext, '');
      if (result.code !== Code.OK) {
        LogUtil.e(this.tag, result.content);
      } else {
        LogUtil.i(this.tag, result.content);
      }
    } catch (error) {
      LogUtil.e(this.tag, error as string);
    }
  }

  getSourceProcessor(inputParam: InputParameter): ISourceCodeProcessor {
    return inputParam.isHandleMultiFiles() ? new MultiFileProcessor(inputParam) : new SingleFileProcessor(inputParam);
  }

  getBaseContext(inputParam: InputParameter): Context {
    return new ContextImpl(inputParam.inputFilePath,
      inputParam.outputFilePath!,
      inputParam.getOptions());
  }
}

abstract class BaseSourceCodeProcessor implements ISourceCodeProcessor {
  inputParam: InputParameter;

  constructor(inputParam: InputParameter) {
    this.inputParam = inputParam;
  }

  abstract process(context: Context, code: string): Promise<ProcessResult>;

  buildProcessorContext(parentContext: Context, inputFile: string): Context {
    return new ContextImpl(inputFile,
      OutputFileHelper.getOutputFilePath(this.inputParam, inputFile),
      parentContext.getOptions());
  }
}

/**
 * 处理单个 d.ts 文件。
 */
export class SingleFileProcessor extends BaseSourceCodeProcessor {

  async process(context: Context, content: string): Promise<ProcessResult> {
    const inputFilePath = context.getInputFile();
    if (!inputFilePath) {
      return {
        code: Code.ERROR,
        content: StringResource.getString(StringResourceId.INPUT_FILE_NOT_FOUND)
      };
    }
    const rawCodeStr = FileUtils.readFileContent(inputFilePath);
    if (StringUtils.isEmpty(rawCodeStr)) {
      return {
        code: Code.ERROR,
        content: StringResource.getString(StringResourceId.INPUT_FILE_CONTENT_EMPTY)
      };
    }

    let preResult = {
      code: Code.OK,
      content: rawCodeStr ? rawCodeStr : ''
    };
    const newContext = this.buildProcessorContext(context, context.getInputFile());
    const logReporter: LogReporter = context.getLogReporter();
    newContext.setLogReporter(logReporter);
    for (let processor of processorRegistry) {
      preResult = await processor.process(newContext, preResult.content);
      if (preResult.code === Code.ERROR) {
        break;
      }
    }
    // 报告落盘
    const reportFilePath: string = OutputFileHelper.getLogReportFilePath(this.inputParam);
    await context.getLogReporter().writeAllResults(reportFilePath);
    if (context.getOptions().isTest) {
      LogUtil.i('jsdoc-tool', `the report file is in ${reportFilePath}.json`);
    } else {
      LogUtil.i('jsdoc-tool', `the report file is in ${reportFilePath}.xlsx`);
    }
    if (preResult.code === Code.OK) {
      preResult.content = `new d.ts file is ${newContext.getOutputFile()}`;
    }
    return preResult;
  }
}

/**
 * 处理文件夹。
 */
export class MultiFileProcessor extends BaseSourceCodeProcessor {
  async process(context: Context, content: string): Promise<ProcessResult> {
    const intpuDir = context.getInputFile();
    if (!intpuDir) {
      return {
        code: Code.ERROR,
        content: StringResource.getString(StringResourceId.INPUT_FILE_NOT_FOUND)
      };
    }
    const allSourceFiles = FileUtils.readFilesInDir(intpuDir, (name) => {
      return name.endsWith(ConstantValue.DTS_EXTENSION);
    });
    const errorSet: Array<ProcessResult> = new Array();
    const logReporter: LogReporter = context.getLogReporter();
    for (const childFile of allSourceFiles) {
      const rawCodeStr = FileUtils.readFileContent(childFile);
      if (StringUtils.isEmpty(rawCodeStr)) {
        errorSet.push({
          code: Code.ERROR,
          content: `${childFile}: ${StringResource.getString(StringResourceId.INPUT_FILE_CONTENT_EMPTY)}`
        });
        continue;
      }
      const newContext = this.buildProcessorContext(context, childFile);
      newContext.setLogReporter(logReporter);
      let preValue = {
        code: Code.OK,
        content: rawCodeStr!
      };

      for (let processor of processorRegistry) {
        preValue = await processor.process(newContext, preValue.content);
        if (preValue.code !== Code.OK) {
          errorSet.push(preValue);
          break;
        }
      }
    }
    // 报告落盘
    const reportFilePath: string = OutputFileHelper.getLogReportFilePath(this.inputParam);
    await context.getLogReporter().writeAllResults(reportFilePath);
    if (context.getOptions().isTest) {
      LogUtil.i('jsdoc-tool', `the report file is in ${reportFilePath}.json`);
    } else {
      LogUtil.i('jsdoc-tool', `the report file is in ${reportFilePath}.xlsx`);
    }
    return {
      code: errorSet.length > 0 ? Code.ERROR : Code.OK,
      content: errorSet.length > 0 ? JSON.stringify(errorSet) :
        `new d.ts file is in ${OutputFileHelper.getMultiOutputDir(this.inputParam)}`
    };
  }
}

/**
 * 整改流程处理器配置，按需添加必要处理流程。
 */
const processorRegistry: Array<ISourceCodeProcessor> = [
  // 原始文件解析
  new RawSourceCodeProcessor(),
  // 同名异步函数处理
  new AsynchronousFunctionProcessor(),
  // 注释整改
  new CommentModificationProcessor(),
  // API调整
  new ApiSplitProcessor(),
  // 新文件输出，日志输出
  new OutputProcessor()
];