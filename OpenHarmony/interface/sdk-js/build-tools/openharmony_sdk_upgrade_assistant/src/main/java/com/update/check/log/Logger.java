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

package com.update.check.log;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.appender.RollingFileAppender;
import org.apache.logging.log4j.core.appender.rolling.SizeBasedTriggeringPolicy;
import org.apache.logging.log4j.core.config.AppenderRef;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.layout.PatternLayout;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Logger
 *
 * @since 23-04-07
 */
public abstract class Logger {
    /**
     * LOGGER_NAME
     *
     * @since 23-04-07
     */
    public static final String LOGGER_NAME = "com.ohos.ui.migration";

    /**
     * exception
     *
     * @param tag     tag
     * @param message message
     */
    public abstract void error(String tag, String message);

    /**
     * info
     *
     * @param tag     tag
     * @param message message
     */
    public abstract void info(String tag, String message);

    /**
     * warn
     *
     * @param tag     tag
     * @param message message
     */
    public abstract void warn(String tag, String message);

    /**
     * d
     *
     * @param tag     tag
     * @param message message
     */
    public abstract void debug(String tag, String message);

    /**
     * init
     *
     * @param logDir logDir
     */
    public static void init(String logDir) {
        System.out.println("configure log directory: " + logDir);
        org.apache.logging.log4j.spi.LoggerContext context = LogManager.getContext(false);
        LoggerContext ctx = null;
        if (context instanceof LoggerContext) {
            ctx = (LoggerContext) context;
        }
        Configuration config = ctx.getConfiguration();
        PatternLayout layout = PatternLayout.newBuilder()
                .withPattern(PatternLayout.SIMPLE_CONVERSION_PATTERN)
                .build();
        List<AppenderRef> refs = new ArrayList<>();
        Appender rollingFileAppender = createRollingFileAppender(logDir, layout, config, refs);
        Appender consoleAppender = createConsoleAppender(layout, config, refs);
        LoggerConfig loggerConfig = LoggerConfig.newBuilder().withAdditivity(false)
                .withLevel(Level.DEBUG)
                .withLoggerName(LOGGER_NAME)
                .withIncludeLocation("true")
                .withRefs(refs.toArray(new AppenderRef[0]))
                .withConfig(config)
                .build();
        loggerConfig.addAppender(rollingFileAppender, null, null);
        loggerConfig.addAppender(consoleAppender, null, null);
        config.addLogger(LOGGER_NAME, loggerConfig);
        ctx.updateLoggers();
    }

    private static Appender createRollingFileAppender(String logDir, PatternLayout layout, Configuration config,
                                                      List<AppenderRef> refs) {
        File logFile = new File(logDir, "updateCheck.log");
        // 5MB = 5 * 1024 * 1024 = 5242880
        SizeBasedTriggeringPolicy policy = SizeBasedTriggeringPolicy.createPolicy("5242880");
        String appenderName = "updateCheck-file";
        Appender appender = RollingFileAppender.newBuilder().withFileName(logFile.getPath())
                .withFilePattern("%d{yyyyMMdd-HHmm}.log.zip")
                .withAppend(true)
                .withPolicy(policy)
                .setName(appenderName)
                .setLayout(layout)
                .setConfiguration(config)
                .build();
        appender.start();
        config.addAppender(appender);
        refs.add(AppenderRef.createAppenderRef(appenderName, null, null));
        return appender;
    }

    private static Appender createConsoleAppender(PatternLayout layout, Configuration config, List<AppenderRef> refs) {
        String appenderName = "check-console";
        Appender appender = ConsoleAppender.newBuilder()
                .setName(appenderName)
                .setLayout(layout)
                .setConfiguration(config)
                .build();
        appender.start();
        config.addAppender(appender);
        refs.add(AppenderRef.createAppenderRef(appenderName, null, null));
        return appender;
    }


    /**
     * createLogger
     *
     * @return logger
     */
    public static Logger createLogger() {
        return new LoggerImpl();
    }
}