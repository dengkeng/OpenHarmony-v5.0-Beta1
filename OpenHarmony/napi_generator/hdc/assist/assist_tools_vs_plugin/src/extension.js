/*
* Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd. 
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

// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const { readFile } = require('./util/VsPluginTool');

var extensionIds = [];
var importCheck = false;

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log('Congratulations, your extension "Kaihong Assist Tools" is now active!');

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with  registerCommand
	// The commandId parameter must match the command field in package.json
	let disposable = vscode.commands.registerCommand('assist_tools', function () {
		// The code you place here will be executed every time your command is executed

		globalPanel = vscode.window.createWebviewPanel(
			'assist tools', // Identifies the type of WebView
			'Kaihong Assist Tools', // Title of the panel displayed to the user
			vscode.ViewColumn.Two, // Display the WebView panel in the form of new columns in the editor
			{
				enableScripts: true, // Enable or disable JS, default is Enable
				retainContextWhenHidden: true, // Keep the WebView state when it is hidden to avoid being reset
			}
		);
		globalPanel.webview.html = getWebviewContent(context);
		let msg;
		globalPanel.webview.onDidReceiveMessage(message => {
			msg = message.msg;
			if (msg == "cancel") {
				globalPanel.dispose();
			} else if (msg == "startApi") {
				const extensionId = 'kaihong.ApiScan';
				installStartExtension(extensionId);
			} else if (msg == "startGn") {
				const extensionId = 'kaihong.gn-gen';
				installStartExtension(extensionId);
			} else if (msg == "startService") {
				const extensionId = 'kaihong.service-gen';
				installStartExtension(extensionId);
			} else if (msg == "startTs") {
				const extensionId = 'kaihong.ts-gen';
				installStartExtension(extensionId);
			} else if (msg == "startNapi") {
				const extensionId = 'kaihong.napi-gen';
				installStartExtension(extensionId);
			} else if (msg == "param") {
				let isSelectToolChain = installExtensions(message);
				startExtensions(isSelectToolChain);
			}
		}, undefined, context.subscriptions);
		// Display a message box to the user
		vscode.window.showInformationMessage('Welcome to use Kaihong Assist Tools!');
	});

	context.subscriptions.push(disposable);
}

function installExtensions(message) {
	importCheck = message.importIsCheck;
	let checkApi = message.checkApi;
	let checkGn = message.checkGn;
	let checkService = message.checkService;
	let checkTs = message.checkTs;
	let checkNapi = message.checkNapi;
	if (importCheck) {
		if (extensionIds.length != 0) {
			extensionIds.length = 0;
		}
		if (checkApi == true) {
			extensionIds.push('kaihong.ApiScan')
		}
		if (checkGn == true) {
			extensionIds.push('kaihong.gn-gen')
		}
		if (checkService == true) {
			extensionIds.push('kaihong.service-gen')
		}
		if (checkTs == true) {
			extensionIds.push('kaihong.ts-gen')
		}
		if (checkNapi == true) {
			extensionIds.push('kaihong.napi-gen')
		}
	}
	startInstallExtensions(extensionIds).catch((error) => {
		console.error(error);
	});
	return importCheck;
}

async function startInstallExtensions(extensionIds) {
	const promises = extensionIds.map(async (extensionId) => {
		const extension = vscode.extensions.getExtension(extensionId);
		if (!extension) {
			await vscode.commands.executeCommand('workbench.extensions.installExtension', extensionId);
			console.log(`扩展插件 ${extensionId} 下载完成`);
		} else {
			console.log(`扩展插件 ${extensionId} 已经下载`);
		}
	});
	await Promise.all(promises);
	console.log('所有扩展插件下载完成');
}

/**
* 执行完毕后启动工具链中下一个插件
*/
function nextPluginExeCommand(nextPluginId) {
    if (nextPluginId == "kaihong.ApiScan") {
		return 'api_scan';
	} else if (nextPluginId == "kaihong.gn-gen") {
		return 'generate_gn';
	} else if (nextPluginId == "kaihong.service-gen") {
		return 'generate_service';
	} else if (nextPluginId == "kaihong.ts-gen") {
		return 'generate_ts';
	} else if (nextPluginId == "kaihong.napi-gen") {
		return 'generate_napi';
	} else {
		return null;
	}
}


function startExtensions(isSelectToolChain) {
	//启动工具链，根据需求启用插件
	let extensionId0 = extensionIds[0];
	//将isSelectToolChain和extensionIds数组传入其他插件
	//启动第一个插件
	let nextStartPlugin = nextPluginExeCommand(extensionId0);
	try {
		vscode.commands.executeCommand(nextStartPlugin, '', isSelectToolChain, extensionIds);
	} catch (error) {
		console.error(error);
	}
}

// 参数单位 毫秒 
function wait(ms) {
    return new Promise(resolve => setTimeout(() => resolve(), ms));
};

async function installStartExtension(extensionId) {
	const extension = vscode.extensions.getExtension(extensionId);
	if (!extension) {
	    try {
		// 下载插件
		vscode.window.showInformationMessage(`Extension ${extensionId} installing...`);
		setTimeout(() => {
			const active = vscode.window.activeInformationMessage;
			if (active && active.message === `Extension ${extensionId} installing...`) {
			  active.dispose();
			}
		}, 8000);
		await vscode.commands.executeCommand('workbench.extensions.installExtension', extensionId);
		vscode.window.showInformationMessage(`Extension ${extensionId} installed successfully.`);
		vscode.window.showInformationMessage(`Extension ${extensionId} activating...`);
		console.log(`Extension ${extensionId} activating...`);
		await wait(1000); // 等待下载插件初始化
		const extensionDone = vscode.extensions.getExtension(extensionId);
		if (extensionDone && extensionDone.isActive) {
			vscode.window.showInformationMessage(`Extension ${extensionId} activated successfully.`);
			console.log(`Extension ${extensionId} activated successfully.`);
		} else {
			console.log('请等待插件初始化完成')
			await wait(1000);
		}
	  } catch (error) {
		console.log(`Failed to install extension ${extensionId}: ${error.message}`);
	  }
	}

	// 启动扩展
	if (extensionId == "kaihong.ApiScan") {
		vscode.commands.executeCommand('api_scan', '', false, '');
	} else if (extensionId == "kaihong.gn-gen") {
		vscode.commands.executeCommand('generate_gn', '', false, '');
	} else if (extensionId == "kaihong.service-gen") {
		vscode.commands.executeCommand('generate_service', '', false, '');
	} else if (extensionId == "kaihong.ts-gen") {
		vscode.commands.executeCommand('generate_ts', '', false, '');
	} else if (extensionId == "kaihong.napi-gen") {
		vscode.commands.executeCommand('generate_napi', '', false, '');
	} 
	else {
		console.error('the toolChain does not include this extension!')
	}
}
  
function getWebviewContent(context) {
	let data = readFile(__dirname + '/vs_plugin_view.html');
	data = getWebViewContent(context, '/vs_plugin_view.html');
	return data.toString();
}

function getWebViewContent(context, templatePath) {
    const resourcePath = path.join(context.extensionPath, templatePath);
    const dirPath = path.dirname(resourcePath);
    let html = fs.readFileSync(resourcePath, 'utf-8');
    html = html.replace(/(<link.+?href="|<script.+?src="|<iframe.+?src="|<img.+?src=")(.+?)"/g, (m, $1, $2) => {
        if ($2.indexOf("https://") < 0) {
            return $1 + globalPanel.webview.asWebviewUri(vscode.Uri.file(path.resolve(dirPath, $2))) + '"';
        } else {
            return $1 + $2+'"';
        }
    });
    return html;
}

// This method is called when your extension is deactivated
function deactivate() {}

module.exports = {
	activate,
	deactivate
}
