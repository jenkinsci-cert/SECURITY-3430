package io.jenkins.security;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CompatibilityTest {

    private static final String REMOTING_JAR_NAME_PATTERN = "remoting[-](.+)[.]jar";

    private static Stream<Arguments> test() throws URISyntaxException {
        return Arrays.stream(Objects.requireNonNull(getRemotingDirectory().list((dir, name) -> name.matches(REMOTING_JAR_NAME_PATTERN)))).map(Arguments::of);
    }
    @ParameterizedTest
    @MethodSource
    public void test(String remotingFileName) throws IOException, URISyntaxException {
        final File remotingFile = new File(getRemotingDirectory(), remotingFileName);
        assertTrue(remotingFile.exists(), "Failed to find remoting " + remotingFileName);
        final byte[] classfile = readClassfileFromRemoting(new ZipFile(remotingFile));
        assertNotNull(Security3430Workaround.innerTransform(classfile), "Failed to transform class file in remoting " + remotingFileName);
    }

    private static File getRemotingDirectory() throws URISyntaxException {
        return new File(Objects.requireNonNull(CompatibilityTest.class.getResource("/old-remoting/remoting-4.0.jar")).toURI().getPath()).getParentFile();
    }

    private static byte[] readClassfileFromRemoting(ZipFile zipFile) throws IOException {
        final ZipEntry entry = zipFile.getEntry("hudson/remoting/RemoteClassLoader$ClassLoaderProxy.class");

        if (entry == null) {
            return null;
        }

        try (InputStream is = zipFile.getInputStream(entry)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            IOUtils.copy(is, baos);
            return baos.toByteArray();
        }
    }
}
