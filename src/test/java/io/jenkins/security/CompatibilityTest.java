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
                "4.0",
                "4.0.1",
                "4.1",
                "4.2",
                "4.2.1",
                "4.3",
                "4.4",
                "4.5",
                "4.6",
                "4.6.1",
                "4.7",
                "4.8",
                "4.9",
                "4.10",
                "4.10.1",
                "4.11",
                "4.11.1",
                "4.11.2",
                "4.12",
                "4.13",
                "4.13.1",
                "4.13.2",
                "4.13.3",
                "4.14",
                "3020.vcc32c3b_cc767",
                "3025.vf64a_a_3da_6b_55",
                "3028.va_a_436db_35078",
                "3044.vb_940a_a_e4f72e",
                "3046.v38db_38a_b_7a_86",
                "3063.v26e24490f041",
                "3068.v09b_895d8da_14",
                "3071.v7e9b_0dc08466",
                "3077.vd69cf116da_6f",
                "3085.vc4c6977c075a",
                "3107.v665000b_51092",
                "3131.vf2b_b_798b_ce99",
                "3142.vcfca_0cd92128",
                "3148.v532a_7e715ee3",
                "3159.vb_8c0ef2b_55a_f",
                "3160.vd76b_9ddd10cc",
                "3174.v2c9e67f8f9df",
                "3176.v207ec082a_8c0",
                "3180.v3dd999d24861",
                "3181.v78543a_987053",
                "3184.vc8c6efb_3b_3d7",
                "3186.vc3b_7249b_87eb_",
                "3190.va_7870fc137d9",
                "3192.v713e3b_039fb_e",
                "3198.v03a_401881f3e",
                "3203.v94ce994fdb_31",
                "3206.3208.v409508a_675ff",
                "3206.vb_15dcf73f6a_9",
                "3241.v4280e2170268",
                "3244.vf7f977e04755",
                "3248.3250.v3277a_8e88c9b_",
                "3248.v65ecb_254c298",
                "3256.3258.v858f3c9a_f69d",
                "3256.v88a_f6e922152",
                "3261.v9c670a_4748a_9").map(Arguments::of);
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
