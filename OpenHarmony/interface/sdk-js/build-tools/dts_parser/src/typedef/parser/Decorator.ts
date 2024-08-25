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

export class DecoratorInfo {
  expression: string = ''; //修饰符名称
  expressionArguments: string[] | undefined = undefined; //修饰符传参，默认为undefined

  constructor(decorator: ts.Decorator) {
    const expression: ts.LeftHandSideExpression = decorator.expression;
    if (ts.isCallExpression(expression)) {
      this.setExpression(expression.expression.getText());
      const args: ts.NodeArray<ts.Expression> = expression.arguments;
      args.forEach((arg: ts.Expression) => {
        this.addExpressionArguments([arg.getText()]);
      });
    }
    if (ts.isIdentifier(expression)) {
      this.setExpression(expression.getText());
    }
  }

  setExpression(expression: string): DecoratorInfo {
    this.expression = expression;
    return this;
  }

  getExpression(): string {
    return this.expression;
  }

  setExpressionArguments(expressionArguments: string[]): DecoratorInfo {
    this.expressionArguments = expressionArguments;
    return this;
  }

  addExpressionArguments(expressionArguments: string[]): DecoratorInfo {
    if (!this.expressionArguments) {
      this.expressionArguments = [];
    }
    this.expressionArguments.push(...expressionArguments);
    return this;
  }

  getExpressionArguments(): string[] | undefined {
    return this.expressionArguments;
  }
}
