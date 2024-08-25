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

package com.update.check.utils;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * MySystemUtils
 *
 * @since 23-04-07
 */
public class MySystemUtils {
    /**
     * isWindows
     *
     * @since 23-04-07
     */
    public static final boolean IS_WINDOWS = System.getProperty("os.name").toLowerCase().startsWith("windows");
    private static final String PATH_SPLIT_STR = IS_WINDOWS ? ";" : ":";
    private static final Collection<String> PATH;
    private static final Collection<String> PATHEXT;

    static {
        Collection<String> localPaths = Collections.emptyList();
        String paths = System.getenv("PATH");
        if (paths != null) {
            localPaths = Arrays.asList(paths.split(PATH_SPLIT_STR));
        }
        PATH = localPaths;

        Collection<String> localPathExt = Collections.emptyList();
        if (IS_WINDOWS) {
            String pathExt = System.getenv("PATHEXT");
            if (pathExt != null) {
                localPathExt = Arrays.asList(pathExt.split(";"));
            }
        }
        PATHEXT = localPathExt;
    }

    /**
     * guessNodeHome
     *
     * @return node home
     */
    public static File guessNodeHome() {
        File nodeFile = guessNodeFile();
        if (nodeFile == null) {
            return null;
        }

        return nodeFile.getParentFile();
    }

    /**
     * guessNodeFile
     *
     * @return node file
     */
    public static File guessNodeFile() {
        return findExecutableFileInPathEnv("node");
    }

    /**
     * guessJavaHome
     *
     * @return java home
     */
    public static File guessJavaHome() {
        File javaFile = guessJavaFile();
        if (javaFile == null) {
            return null;
        }

        return javaFile.getParentFile().getParentFile();
    }

    /**
     * guessJavaFile
     *
     * @return java file
     */
    public static File guessJavaFile() {
        String javaHome = System.getenv("JAVA_HOME");
        if (javaHome != null) {
            File javaFile = getExecutableFile(new File(javaHome, "bin"), "java");
            if (javaFile != null) {
                return javaFile;
            }
        }

        return findExecutableFileInPathEnv("java");
    }

    /**
     * findExecutableFileInPathEnv
     *
     * @param fileName fileName
     * @return fileInPathEnv
     */
    public static File findExecutableFileInPathEnv(String fileName) {
        Objects.requireNonNull(fileName);
        List<String> fileNames = new LinkedList<>();
        fileNames.add(fileName);
        if (IS_WINDOWS) {
            fileNames.addAll(PATHEXT.stream().map(x -> fileName + x).collect(Collectors.toList()));
        }
        return findExecutableFileInPathEnv(fileNames);
    }

    private static File findExecutableFileInPathEnv(Collection<String> fileNames) {
        Objects.requireNonNull(fileNames);
        for (String path : PATH) {
            for (String fileName : fileNames) {
                File ioFile = new File(path, fileName);
                if (isExecutableFile(ioFile)) {
                    return ioFile;
                }
            }
        }
        return null;
    }

    private static boolean isExecutableFile(File ioFile) {
        if (!ioFile.exists()) {
            return false;
        }

        if (!ioFile.isFile()) {
            return false;
        }
        return ioFile.canExecute();
    }

    /**
     * getExecutableFile
     *
     * @param ioDir    ioDir
     * @param fileName fileName
     * @return executableFile
     */
    public static File getExecutableFile(String ioDir, String fileName) {
        if (ioDir == null) {
            return null;
        }

        return getExecutableFile(new File(ioDir), fileName);
    }

    /**
     * getExecutableFile
     *
     * @param ioDir    ioDir
     * @param fileName fileName
     * @return executableFile
     */
    public static File getExecutableFile(File ioDir, String fileName) {
        Objects.requireNonNull(ioDir);
        Objects.requireNonNull(fileName);

        File ioFile = new File(ioDir, fileName);
        if (isExecutableFile(ioFile)) {
            return ioFile;
        }

        for (String ext : PATHEXT) {
            ioFile = new File(ioDir, fileName + ext);
            if (isExecutableFile(ioFile)) {
                return ioFile;
            }
        }
        return null;
    }
}
