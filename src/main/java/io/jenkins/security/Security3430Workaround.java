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
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Security3430Workaround implements ClassFileTransformer {
    private static final Logger LOGGER = Logger.getLogger(Security3430Workaround.class.getName());
    public static final String METHOD_NAME = "fetchJar";

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

        LOGGER.log(Level.SEVERE, () -> "SECURITY-3430 Workaround: Failed to find the '" + METHOD_NAME + "' in the class file, cannot prevent exploitation.");
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
        try {
            final int offset = findMethodNameInConstantPool(classfileBuffer);
            return innerReplace(classfileBuffer, offset);
        } catch (Exception ex) {
            LOGGER.log(Level.WARNING, ex, () -> "Failed to replace");
            return null;
        }
    }

    private static int findMethodNameInConstantPool(byte[] classfileBuffer) {
        final CountingInputStream counter = new CountingInputStream(new ByteArrayInputStream(classfileBuffer));
        try (DataInputStream dis = new DataInputStream(counter)) {
            final byte[] magic = dis.readNBytes(4);
            if (!Arrays.equals(magic, new byte[] { (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE })) {
                throw new IllegalArgumentException("Not a class file");
            }
            final int version = dis.readInt();
            if (version > 0x42) { // 66, Java 22
                throw new IllegalArgumentException("Unsupported class file version: " + version);
            }
            final int constantPoolEntries = dis.readUnsignedShort();
            int currentEntry = 1;
            while (currentEntry < constantPoolEntries) {
                final int tag = dis.readUnsignedByte();
                final int offset = counter.getOffset();
                // https://docs.oracle.com/javase/specs/jvms/se22/html/jvms-4.html#jvms-4.4
                // https://en.wikipedia.org/wiki/Java_class_file#The_constant_pool
                switch (tag) {
                    case 7:
                    case 8:
                    case 16:
                    case 19:
                    case 20:
                        // 2 bytes
                        dis.readShort();
                        currentEntry++;
                        continue;
                    case 15:
                        // 3 bytes
                        dis.readShort();
                        dis.readByte();
                        currentEntry++;
                        continue;
                    case 3:
                    case 4:
                    case 9:
                    case 10:
                    case 11:
                    case 12:
                    case 17:
                    case 18:
                        // 4 bytes
                        dis.readInt();
                        currentEntry++;
                        continue;
                    case 5:
                    case 6:
                        // 8 bytes
                        dis.readInt();
                        dis.readInt();
                        currentEntry++;
                        continue;
                    case 1:
                        // Variable length string in "modified UTF".
                        // Per https://en.wikipedia.org/wiki/UTF-8#Modified_UTF-8 class files use the same encoding.
                        final String str = dis.readUTF();
                        if (METHOD_NAME.equals(str)) {
                            LOGGER.log(Level.FINE, () -> "Found string: " + str + " at offset: " + offset);
                            return offset + 2; // add the length prefix, see #readUTF
                        }
                        currentEntry++;
                        continue;
                    default:
                        throw new IllegalArgumentException("Unknown constant pool entry type: " + tag);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        throw new IllegalArgumentException("Failed to find '" + METHOD_NAME + "' in constant pool");
    }

    private static class CountingInputStream extends FilterInputStream {
        private int offset;
        protected CountingInputStream(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            offset++;
            return super.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            offset += len;
            return super.read(b, off, len);
        }

        @Override
        public long skip(long n) throws IOException {
            offset += n;
            return super.skip(n);
        }

        public int getOffset() {
            return offset;
        }
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
