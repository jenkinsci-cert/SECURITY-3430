/*
 * The MIT License
 *
 * Copyright (c) 2024, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package io.jenkins.security;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.File;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Security3430Workaround implements ClassFileTransformer {
    private static final Logger LOGGER = Logger.getLogger(Security3430Workaround.class.getName());

    @SuppressFBWarnings(value = "DM_EXIT", justification = "Failure to transform might result in unsafe state, so shutting down is intentional")
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (!className.equals("hudson/remoting/RemoteClassLoader$ClassLoaderProxy")) {
            LOGGER.log(Level.FINEST, () -> "SECURITY-3430 Workaround: Skipping transformation because class name does not match: " + className);
            return null;
        }

        final String systemPropertyName = Security3430Workaround.class.getName() + ".DISABLE";
        if (Boolean.getBoolean(systemPropertyName)) {
            LOGGER.log(Level.INFO, () -> "SECURITY-3430 Workaround: Skipping transformation of " + className + " because " + systemPropertyName + " is set");
            return null;
        }

        LOGGER.log(Level.INFO, () -> "SECURITY-3430 Workaround: Performing transformation of " + className);

        final byte[] transformed = innerTransform(classfileBuffer);
        if (transformed != null) {
            return transformed;
        }

        LOGGER.log(Level.SEVERE, () -> "SECURITY-3430 Workaround: Failed to find the 'fetchJar' in the class file, cannot prevent exploitation.");
        final String skipShutdownPropertyName = Security3430Workaround.class.getName() + ".SKIP_SHUTDOWN";
        if (Boolean.getBoolean(skipShutdownPropertyName)) {
            LOGGER.log(Level.SEVERE, () -> "SECURITY-3430 Workaround: Skipping shutdown because " + skipShutdownPropertyName + " is set. The instance is not protected from SECURITY-3430.");
        } else {
            LOGGER.log(Level.SEVERE, () -> "SECURITY-3430 Workaround: Shutting down.");
            System.exit(1);
        }
        return null;
    }

    static byte[] innerTransform(byte[] classfileBuffer) {
        byte[] needle = "fetchJar".getBytes(StandardCharsets.US_ASCII);

        OUTER: for (int i = 0; i <= classfileBuffer.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (classfileBuffer[i+j] != needle[j]) {
                    continue OUTER;
                }
                if (j == needle.length - 1) {
                    return innerReplace(classfileBuffer, i);
                }
            }
        }

        return null;
    }

    private static byte[] innerReplace(byte[] classfileBuffer, int offset) {
        final byte[] output = Arrays.copyOf(classfileBuffer, classfileBuffer.length);
        output[offset] = 'r'; // fetchJar -> retchJar :-)
        return output;
    }

    public static void premain(String args, Instrumentation instrumentation) {
        LOGGER.log(Level.INFO, () -> "Setting up " + Security3430Workaround.class.getName());
        instrumentation.addTransformer(new Security3430Workaround());
    }

    @SuppressFBWarnings(value = {"PATH_TRAVERSAL_IN", "DM_EXIT"}, justification = "CLI behavior")
    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.err.println("This file is a Java agent addressing SECURITY-3430/CVE-2024-43044 in older releases of Jenkins by patching bytecode.");
            System.err.println("Usage:");
            System.err.println("    java -javaagent:/path/to/security3430-workaround.jar -jar jenkins.war");
            System.err.println("Additionally, this file can be used as an executable jar to patch a RemoteClassLoader$ClassLoaderProxy.class file.");
            System.err.println("Usage:");
            System.err.println("    java -jar /path/to/security3430-workaround.jar <source> <target>");
            System.exit(1);
            return;
        }
        final byte[] original = Files.readAllBytes(new File(args[0]).toPath());
        final byte[] modified = innerTransform(original);
        if (modified == null) {
            System.err.println("Failed to transform the specified file. Is it a RemoteClassLoader$ClassLoaderProxy.class?");
            System.exit(1);
            return;
        }
        Files.write(new File(args[1]).toPath(), modified);
    }
}
