/*
 * Copyright 2026 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.openrewrite.java.netty;

import org.junit.jupiter.api.Test;
import org.openrewrite.DocumentExample;
import org.openrewrite.InMemoryExecutionContext;
import org.openrewrite.java.JavaParser;
import org.openrewrite.test.RecipeSpec;
import org.openrewrite.test.RewriteTest;

import static org.openrewrite.java.Assertions.java;

class SelfSignedCertificateToCertificateBuilderTest implements RewriteTest {

    @Override
    public void defaults(RecipeSpec spec) {
        spec.recipe(new SelfSignedCertificateToCertificateBuilder())
          .parser(JavaParser.fromJavaVersion().classpathFromResources(new InMemoryExecutionContext(),
            "netty-handler", "netty-pkitesting"));
    }

    @DocumentExample
    @Test
    void replaceSelfSignedCertificate() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.io.File;
              import java.security.PrivateKey;
              import java.security.cert.CertificateException;
              import java.security.cert.X509Certificate;

              class Test {
                  void test() throws CertificateException {
                      SelfSignedCertificate ssc = new SelfSignedCertificate();
                      X509Certificate cert = ssc.cert();
                      PrivateKey key = ssc.key();
                      File certificate = ssc.certificate();
                      File privateKey = ssc.privateKey();
                      ssc.delete();
                  }
              }
              """,
            """
              import io.netty.pkitesting.CertificateBuilder;
              import io.netty.pkitesting.X509Bundle;

              import java.io.File;
              import java.security.PrivateKey;
              import java.security.cert.X509Certificate;

              class Test {
                  void test() throws Exception {
                      X509Bundle ssc = new CertificateBuilder().subject("CN=localhost").setIsCertificateAuthority(true).rsa2048().buildSelfSigned();
                      X509Certificate cert = ssc.getCertificate();
                      PrivateKey key = ssc.getKeyPair().getPrivate();
                      File certificate = ssc.toTempCertChainPem();
                      File privateKey = ssc.toTempPrivateKeyPem();
                  }
              }
              """
          )
        );
    }

    @Test
    void fqdnLiteral() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              class Test {
                  SelfSignedCertificate ssc;

                  void setUp() throws Exception {
                      ssc = new SelfSignedCertificate("example.com");
                  }
              }
              """,
            """
              import io.netty.pkitesting.CertificateBuilder;
              import io.netty.pkitesting.X509Bundle;

              class Test {
                  X509Bundle ssc;

                  void setUp() throws Exception {
                      ssc = new CertificateBuilder().subject("CN=example.com").setIsCertificateAuthority(true).rsa2048().buildSelfSigned();
                  }
              }
              """
          )
        );
    }

    @Test
    void fqdnExpression() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              class Test {
                  SelfSignedCertificate create(String host) throws Exception {
                      return new SelfSignedCertificate(host);
                  }
              }
              """,
            """
              import io.netty.pkitesting.CertificateBuilder;
              import io.netty.pkitesting.X509Bundle;

              class Test {
                  X509Bundle create(String host) throws Exception {
                      return new CertificateBuilder().subject("CN=" + host).setIsCertificateAuthority(true).rsa2048().buildSelfSigned();
                  }
              }
              """
          )
        );
    }

    @Test
    void unsupportedConstructorLeavesFileUnchanged() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.util.Date;

              class Test {
                  void test(Date notBefore, Date notAfter) throws Exception {
                      SelfSignedCertificate ssc = new SelfSignedCertificate(notBefore, notAfter);
                      SelfSignedCertificate other = new SelfSignedCertificate();
                  }
              }
              """
          )
        );
    }

    @Test
    void deleteInExpressionLeavesFileUnchanged() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              class Test {
                  Runnable test() throws Exception {
                      SelfSignedCertificate ssc = new SelfSignedCertificate();
                      return ssc::delete;
                  }
              }
              """
          )
        );
    }

    @Test
    void widenCatchClause() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.security.cert.CertificateException;

              class Test {
                  SelfSignedCertificate ssc;

                  void setUp() {
                      try {
                          ssc = new SelfSignedCertificate();
                      } catch (CertificateException e) {
                          throw new IllegalStateException(e);
                      }
                  }
              }
              """,
            """
              import io.netty.pkitesting.CertificateBuilder;
              import io.netty.pkitesting.X509Bundle;

              class Test {
                  X509Bundle ssc;

                  void setUp() {
                      try {
                          ssc = new CertificateBuilder().subject("CN=localhost").setIsCertificateAuthority(true).rsa2048().buildSelfSigned();
                      } catch (Exception e) {
                          throw new IllegalStateException(e);
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void widenGeneralSecurityException() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.io.IOException;
              import java.security.GeneralSecurityException;

              class Test {
                  SelfSignedCertificate create() throws IOException, GeneralSecurityException {
                      return new SelfSignedCertificate();
                  }
              }
              """,
            """
              import io.netty.pkitesting.CertificateBuilder;
              import io.netty.pkitesting.X509Bundle;

              import java.io.IOException;

              class Test {
                  X509Bundle create() throws IOException, Exception {
                      return new CertificateBuilder().subject("CN=localhost").setIsCertificateAuthority(true).rsa2048().buildSelfSigned();
                  }
              }
              """
          )
        );
    }

    @Test
    void addThrowsForTempFiles() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.io.File;

              class Test {
                  File certificate(SelfSignedCertificate ssc) {
                      return ssc.certificate();
                  }

                  File privateKey(SelfSignedCertificate ssc) throws InterruptedException {
                      return ssc.privateKey();
                  }
              }
              """,
            """
              import io.netty.pkitesting.X509Bundle;

              import java.io.File;
              import java.io.IOException;

              class Test {
                  File certificate(X509Bundle ssc) throws IOException {
                      return ssc.toTempCertChainPem();
                  }

                  File privateKey(X509Bundle ssc) throws InterruptedException, IOException {
                      return ssc.toTempPrivateKeyPem();
                  }
              }
              """
          )
        );
    }

    @Test
    void propagateFromTryWithoutMatchingCatch() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.security.cert.CertificateException;

              class Test {
                  void test() throws CertificateException {
                      try {
                          SelfSignedCertificate ssc = new SelfSignedCertificate();
                      } catch (IllegalStateException e) {
                      }
                  }
              }
              """,
            """
              import io.netty.pkitesting.CertificateBuilder;
              import io.netty.pkitesting.X509Bundle;

              class Test {
                  void test() throws Exception {
                      try {
                          X509Bundle ssc = new CertificateBuilder().subject("CN=localhost").setIsCertificateAuthority(true).rsa2048().buildSelfSigned();
                      } catch (IllegalStateException e) {
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void overridingMethodLeavesFileUnchanged() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.io.File;
              import java.util.function.Supplier;

              class Test implements Supplier<File> {
                  SelfSignedCertificate ssc;

                  @Override
                  public File get() {
                      return ssc.certificate();
                  }
              }
              """
          )
        );
    }

    @Test
    void lambdaLeavesFileUnchanged() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.util.concurrent.Callable;

              class Test {
                  Callable<SelfSignedCertificate> test() {
                      return () -> new SelfSignedCertificate();
                  }
              }
              """
          )
        );
    }

    @Test
    void callerWithoutHandlingLeavesFileUnchanged() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.security.cert.CertificateException;

              class Certs {
                  static SelfSignedCertificate create() throws CertificateException {
                      return new SelfSignedCertificate();
                  }
              }
              """
          ),
          //language=java
          java(
            """
              import java.security.cert.CertificateException;

              class Server {
                  void start() throws CertificateException {
                      Certs.create();
                  }
              }
              """
          )
        );
    }

    @Test
    void callerHandlingExceptionAllowsThrowsChange() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.security.cert.CertificateException;

              class Certs {
                  static SelfSignedCertificate create() throws CertificateException {
                      return new SelfSignedCertificate();
                  }
              }
              """,
            """
              import io.netty.pkitesting.CertificateBuilder;
              import io.netty.pkitesting.X509Bundle;

              class Certs {
                  static X509Bundle create() throws Exception {
                      return new CertificateBuilder().subject("CN=localhost").setIsCertificateAuthority(true).rsa2048().buildSelfSigned();
                  }
              }
              """
          ),
          //language=java
          java(
            """
              class Server {
                  void start() throws Exception {
                      Certs.create();
                  }
              }
              """
          )
        );
    }

    @Test
    void constructorLeavesFileUnchanged() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.security.cert.CertificateException;

              class Test {
                  final SelfSignedCertificate ssc;

                  Test() throws CertificateException {
                      ssc = new SelfSignedCertificate();
                  }
              }
              """
          )
        );
    }

    @Test
    void rethrowLeavesFileUnchanged() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.security.cert.CertificateException;

              class Test {
                  SelfSignedCertificate ssc;

                  void setUp() throws CertificateException {
                      try {
                          ssc = new SelfSignedCertificate();
                      } catch (CertificateException e) {
                          System.err.println(e.getMessage());
                          throw e;
                      }
                  }
              }
              """
          )
        );
    }

    @Test
    void otherCallsInTryLeavesFileUnchanged() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              import java.security.cert.CertificateException;

              class Test {
                  SelfSignedCertificate ssc;

                  void setUp() {
                      try {
                          ssc = new SelfSignedCertificate();
                          init();
                      } catch (CertificateException e) {
                          throw new IllegalStateException(e);
                      }
                  }

                  void init() {
                  }
              }
              """
          )
        );
    }

    @Test
    void passedToExternalConstructorLeavesFileUnchanged() {
        rewriteRun(
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              class Helper {
                  Helper(SelfSignedCertificate ssc) {
                  }
              }
              """
          ),
          //language=java
          java(
            """
              import io.netty.handler.ssl.util.SelfSignedCertificate;

              class Test {
                  void test() throws Exception {
                      new Helper(new SelfSignedCertificate());
                  }
              }
              """
          )
        );
    }
}
