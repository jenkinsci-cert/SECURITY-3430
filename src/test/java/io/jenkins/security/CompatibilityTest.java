package io.jenkins.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class CompatibilityTest {
    private static Stream<Arguments> test() {
        return Stream.of(
                Arguments.of("4.0"),
                Arguments.of("4.0.1"),
                Arguments.of("4.1"),
                Arguments.of("4.2"),
                Arguments.of("4.2.1"),
                Arguments.of("4.3"),
                Arguments.of("4.4"),
                Arguments.of("4.5"),
                Arguments.of("4.6"),
                Arguments.of("4.6.1"),
                Arguments.of("4.7"),
                Arguments.of("4.8"),
                Arguments.of("4.9"),
                Arguments.of("4.10"),
                Arguments.of("4.10.1"),
                Arguments.of("4.11"),
                Arguments.of("4.11.1"),
                Arguments.of("4.11.2"),
                Arguments.of("4.12"),
                Arguments.of("4.13"),
                Arguments.of("4.13.1"),
                Arguments.of("4.13.2"),
                Arguments.of("4.13.3"),
                Arguments.of("4.14"),
                Arguments.of("3020.vcc32c3b_cc767"),
                Arguments.of("3025.vf64a_a_3da_6b_55"),
                Arguments.of("3028.va_a_436db_35078"),
                Arguments.of("3044.vb_940a_a_e4f72e"),
                Arguments.of("3046.v38db_38a_b_7a_86"),
                Arguments.of("3063.v26e24490f041"),
                Arguments.of("3068.v09b_895d8da_14"),
                Arguments.of("3071.v7e9b_0dc08466"),
                Arguments.of("3077.vd69cf116da_6f"),
                Arguments.of("3085.vc4c6977c075a"),
                Arguments.of("3107.v665000b_51092"),
                Arguments.of("3131.vf2b_b_798b_ce99"),
                Arguments.of("3142.vcfca_0cd92128"),
                Arguments.of("3148.v532a_7e715ee3"),
                Arguments.of("3159.vb_8c0ef2b_55a_f"),
                Arguments.of("3160.vd76b_9ddd10cc"),
                Arguments.of("3174.v2c9e67f8f9df"),
                Arguments.of("3176.v207ec082a_8c0"),
                Arguments.of("3180.v3dd999d24861"),
                Arguments.of("3181.v78543a_987053"),
                Arguments.of("3184.vc8c6efb_3b_3d7"),
                Arguments.of("3186.vc3b_7249b_87eb_"),
                Arguments.of("3190.va_7870fc137d9"),
                Arguments.of("3192.v713e3b_039fb_e"),
                Arguments.of("3198.v03a_401881f3e"),
                Arguments.of("3203.v94ce994fdb_31"),
                Arguments.of("3206.3208.v409508a_675ff"),
                Arguments.of("3206.vb_15dcf73f6a_9"),
                Arguments.of("3241.v4280e2170268"),
                Arguments.of("3244.vf7f977e04755"),
                Arguments.of("3248.3250.v3277a_8e88c9b_"),
                Arguments.of("3248.v65ecb_254c298"),
                Arguments.of("3256.3258.v858f3c9a_f69d"),
                Arguments.of("3256.v88a_f6e922152"),
                Arguments.of("3261.v9c670a_4748a_9"));
    }
    @ParameterizedTest
    @MethodSource
    public void test(String version) throws IOException {
        final URL remotingJar = getClass().getResource("/old-remoting/remoting-" + version + ".jar");
        assertNotNull(remotingJar, "Failed to find remoting " + version);
        final byte[] classfile = readClassfileFromRemoting(remotingJar.openStream());
        if (classfile == null) {
            fail("Failed to find class file in remoting " + version);
        }
        assertNotNull(Security3430Workaround.innerTransform(classfile), "Failed to transform class file in remoting " + version);
    }

    private byte[] readClassfileFromRemoting(InputStream input) {
        try (ZipInputStream zis = new ZipInputStream(input)) {
            ZipEntry entry = zis.getNextEntry();
            while (entry != null) {
                if (entry.getName().equals("hudson/remoting/RemoteClassLoader$ClassLoaderProxy.class")) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    IOUtils.copy(zis, baos);
                    return baos.toByteArray();
                }
                entry = zis.getNextEntry();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return null;
    }
}
