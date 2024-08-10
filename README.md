# SECURITY-3430 Workaround

This is a Java agent for use with Jenkins controllers that do not have the fix for [SECURITY-3430](https://www.jenkins.io/security/advisory/2024-08-07/#SECURITY-3430) (i.e., up to and including 2.470 and LTS 2.452.3).

## Mechanism and Compatibility

It transforms the definition of the class containing the SECURITY-3430 vulnerability to prevent exploitation.
If that fails for some reason, **Jenkins is forcibly stopped**.

This workaround will completely block `ClassLoaderProxy#fetchJar` and is therefore incompatible with the affected functionality of the plugins mentioned in the [security advisory](https://www.jenkins.io/security/advisory/2024-08-07/), unlike the regular fix.

This workaround has been tested successfully with several recent releases of Jenkins from the last few years.

WARNING: Due to how this workaround works, we strongly recommend that you regularly take backups of Jenkins, and deploy the workaround progressively.

## Usage

### Use as Java agent (standard use case)

Protect the Jenkins controller process from exploitation:

```bash
java -javaagent:/path/to/security3430-workaround.jar -jar jenkins.war
```

### Standalone use

Apply the transformation to the specified `RemoteClassLoader$ClassLoaderProxy.class` class file and write the result to a different file:

```bash
java -jar /path/to/security3430-workaround.jar <source file> <target file>
```

This could be used to create minimally modified `remoting.jar` files.

## Configuration

Two Java system properties can be set to change the behavior of this Java agent:

* `io.jenkins.security.Security3430Workaround.DISABLE`:
  Set this to `true` to disable the class transformation.
* `io.jenkins.security.Security3430Workaround.SKIP_SHUTDOWN`:
  Set this to `true` to not stop the Jenkins process when class transformation fails.
  Only recommended in specific narrow situations, e.g., when closely monitoring log messages (see below).

Both need to set before the class is loaded and an attempt to transform is made, ideally as a `-D` command line option.

## Logging

Log messages use the `io.jenkins.security.Security3430Workaround` logger.
Messages logged on `SEVERE` indicate a failure to transform.

## Testing

Run the following code in the script console of a connected Jenkins agent to confirm the effectiveness of this workaround:

```groovy
def cl = Thread.currentThread().getContextClassLoader().proxy
cl.fetchJar(new URL('file:/path/to/jenkins/home/secrets/master.key'))
```

With neither fix nor workaround, this will print a message like the following, indicating successful exploitation: `Result: [B@23edd8a0`

With this workaround applied, this will throw an `AbstractMethodError` and print a long stack trace.

## License

Licensed under the terms of the MIT License. Copyright 2024 CloudBees, Inc.
