# Changelog — AtlaSent Java SDK

## Unreleased

- Breaking: minimum Java version is now 17. The build targets
  `maven.compiler.release` 17 and CI tests JDK 17 and 21 (JDK 11 dropped),
  so the JUnit Jupiter 6 upgrade (#563), which requires Java 17, can land.
