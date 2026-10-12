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

import lombok.Getter;
import org.jspecify.annotations.Nullable;
import org.openrewrite.Cursor;
import org.openrewrite.ExecutionContext;
import org.openrewrite.Preconditions;
import org.openrewrite.ScanningRecipe;
import org.openrewrite.Tree;
import org.openrewrite.TreeVisitor;
import org.openrewrite.internal.ListUtils;
import org.openrewrite.java.ChangeType;
import org.openrewrite.java.JavaIsoVisitor;
import org.openrewrite.java.JavaParser;
import org.openrewrite.java.JavaTemplate;
import org.openrewrite.java.JavaVisitor;
import org.openrewrite.java.MethodMatcher;
import org.openrewrite.java.search.UsesType;
import org.openrewrite.java.tree.Expression;
import org.openrewrite.java.tree.J;
import org.openrewrite.java.tree.JContainer;
import org.openrewrite.java.tree.JRightPadded;
import org.openrewrite.java.tree.JavaSourceFile;
import org.openrewrite.java.tree.JavaType;
import org.openrewrite.java.tree.NameTree;
import org.openrewrite.java.tree.Space;
import org.openrewrite.java.tree.TypeTree;
import org.openrewrite.java.tree.TypeUtils;
import org.openrewrite.marker.Markers;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;

public class SelfSignedCertificateToCertificateBuilder extends ScanningRecipe<SelfSignedCertificateToCertificateBuilder.Accumulator> {

    private static final String SELF_SIGNED_CERTIFICATE = "io.netty.handler.ssl.util.SelfSignedCertificate";
    private static final String X509_BUNDLE = "io.netty.pkitesting.X509Bundle";
    private static final String CERTIFICATE_BUILDER = "io.netty.pkitesting.CertificateBuilder";
    private static final String CERTIFICATE_EXCEPTION = "java.security.cert.CertificateException";
    private static final String GENERAL_SECURITY_EXCEPTION = "java.security.GeneralSecurityException";
    private static final String EXCEPTION = "java.lang.Exception";
    private static final String IO_EXCEPTION = "java.io.IOException";
    private static final String THROWABLE = "java.lang.Throwable";
    private static final String OBJECT = "java.lang.Object";

    private static final MethodMatcher NO_ARG_CONSTRUCTOR = new MethodMatcher(SELF_SIGNED_CERTIFICATE + " <constructor>()");
    private static final MethodMatcher FQDN_CONSTRUCTOR = new MethodMatcher(SELF_SIGNED_CERTIFICATE + " <constructor>(String)");
    private static final MethodMatcher CERT = new MethodMatcher(SELF_SIGNED_CERTIFICATE + " cert()");
    private static final MethodMatcher KEY = new MethodMatcher(SELF_SIGNED_CERTIFICATE + " key()");
    private static final MethodMatcher CERTIFICATE = new MethodMatcher(SELF_SIGNED_CERTIFICATE + " certificate()");
    private static final MethodMatcher PRIVATE_KEY = new MethodMatcher(SELF_SIGNED_CERTIFICATE + " privateKey()");
    private static final MethodMatcher DELETE = new MethodMatcher(SELF_SIGNED_CERTIFICATE + " delete()");

    private static final String REQUIRED_THROWS = "REQUIRED_THROWS";
    private static final String WIDEN_CATCH = "WIDEN_CATCH";

    @Getter
    final String displayName = "Replace `SelfSignedCertificate` with `CertificateBuilder` from `netty-pkitesting`";

    @Getter
    final String description = "Netty 4.2 deprecates `SelfSignedCertificate` in favor of the `CertificateBuilder` from the new " +
            "`netty-pkitesting` module. Replaces `new SelfSignedCertificate()` with an equivalent self-signed `X509Bundle`, " +
            "and migrates `cert()`, `key()`, `certificate()`, `privateKey()` and `delete()` calls. " +
            "Source files using any other `SelfSignedCertificate` API are left unchanged.";

    @Getter
    final Set<String> tags = singleton("netty");

    @Getter
    final Duration estimatedEffortPerOccurrence = Duration.ofMinutes(5);

    public static class Accumulator {
        /**
         * Methods (by declaring type and name) with a call site anywhere in the repository that does not
         * already catch or declare {@code Exception} or {@code IOException} respectively.
         */
        final Set<String> unhandledException = new HashSet<>();
        final Set<String> unhandledIOException = new HashSet<>();

        Set<String> unhandled(String exception) {
            return EXCEPTION.equals(exception) ? unhandledException : unhandledIOException;
        }
    }

    @Override
    public Accumulator getInitialValue(ExecutionContext ctx) {
        return new Accumulator();
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getScanner(Accumulator acc) {
        return new JavaIsoVisitor<ExecutionContext>() {
            @Override
            public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, ExecutionContext ctx) {
                recordCallSite(method.getMethodType());
                return super.visitMethodInvocation(method, ctx);
            }

            @Override
            public J.NewClass visitNewClass(J.NewClass newClass, ExecutionContext ctx) {
                recordCallSite(newClass.getConstructorType());
                return super.visitNewClass(newClass, ctx);
            }

            @Override
            public J.MemberReference visitMemberReference(J.MemberReference memberRef, ExecutionContext ctx) {
                // The functional interface determines which checked exceptions a method reference may throw
                if (memberRef.getMethodType() != null) {
                    acc.unhandledException.add(methodKey(memberRef.getMethodType()));
                    acc.unhandledIOException.add(methodKey(memberRef.getMethodType()));
                }
                return super.visitMemberReference(memberRef, ctx);
            }

            private void recordCallSite(JavaType.@Nullable Method methodType) {
                if (methodType == null) {
                    return;
                }
                if (findHandler(getCursor(), EXCEPTION, null) == null) {
                    acc.unhandledException.add(methodKey(methodType));
                }
                if (findHandler(getCursor(), IO_EXCEPTION, null) == null) {
                    acc.unhandledIOException.add(methodKey(methodType));
                }
            }
        };
    }

    @Override
    public TreeVisitor<?, ExecutionContext> getVisitor(Accumulator acc) {
        return Preconditions.check(new UsesType<>(SELF_SIGNED_CERTIFICATE, false), new JavaVisitor<ExecutionContext>() {

            @Override
            public @Nullable J visit(@Nullable Tree tree, ExecutionContext ctx) {
                if (tree instanceof J.CompilationUnit && !isFullySupported((J.CompilationUnit) tree, acc)) {
                    return (J) tree;
                }
                return super.visit(tree, ctx);
            }

            @Override
            public J visitCompilationUnit(J.CompilationUnit cu, ExecutionContext ctx) {
                J j = super.visitCompilationUnit(cu, ctx);
                if (j != cu) {
                    doAfterVisit(new ChangeType(SELF_SIGNED_CERTIFICATE, X509_BUNDLE, null).getVisitor());
                }
                return j;
            }

            @Override
            public J visitMethodDeclaration(J.MethodDeclaration method, ExecutionContext ctx) {
                J.MethodDeclaration m = (J.MethodDeclaration) super.visitMethodDeclaration(method, ctx);
                Set<String> requiredThrows = getCursor().getMessage(REQUIRED_THROWS);
                if (requiredThrows != null) {
                    // `Exception` first, as it also covers `IOException`
                    if (requiredThrows.contains(EXCEPTION) && !throwsCovers(m, EXCEPTION)) {
                        m = addThrowsException(m);
                        maybeRemoveImport(CERTIFICATE_EXCEPTION);
                        maybeRemoveImport(GENERAL_SECURITY_EXCEPTION);
                    }
                    if (requiredThrows.contains(IO_EXCEPTION) && !throwsCovers(m, IO_EXCEPTION)) {
                        m = addThrows(m, newIdentifier(Space.SINGLE_SPACE, "IOException", IO_EXCEPTION));
                        maybeAddImport(IO_EXCEPTION);
                    }
                }
                return m;
            }

            @Override
            public J visitTry(J.Try tryable, ExecutionContext ctx) {
                J.Try t = (J.Try) super.visitTry(tryable, ctx);
                if (getCursor().getMessage(WIDEN_CATCH, false)) {
                    t = t.withCatches(ListUtils.mapLast(t.getCatches(), c -> {
                        J.VariableDeclarations param = c.getParameter().getTree();
                        J.VariableDeclarations.NamedVariable caught = param.getVariables().get(0);
                        TypeTree typeExpression = param.getTypeExpression();
                        J.Identifier exception = newIdentifier(typeExpression == null ? Space.EMPTY : typeExpression.getPrefix(), "Exception", EXCEPTION);
                        JavaType.Variable oldVariableType = caught.getVariableType();
                        JavaType.Variable newVariableType = oldVariableType == null ? null : oldVariableType.withType(exception.getType());
                        J.Block body = (J.Block) new JavaIsoVisitor<Integer>() {
                            @Override
                            public J.Identifier visitIdentifier(J.Identifier identifier, Integer p) {
                                J.Identifier i = super.visitIdentifier(identifier, p);
                                if (refersTo(i, caught)) {
                                    i = i.withType(exception.getType()).withFieldType(newVariableType);
                                }
                                return i;
                            }
                        }.visitNonNull(c.getBody(), 0);
                        return c.withBody(body).withParameter(c.getParameter().withTree(param
                                .withTypeExpression(exception)
                                .withVariables(singletonList(caught
                                        .withName(caught.getName().withType(exception.getType()).withFieldType(newVariableType))
                                        .withType(exception.getType())))));
                    }));
                    maybeRemoveImport(CERTIFICATE_EXCEPTION);
                    maybeRemoveImport(GENERAL_SECURITY_EXCEPTION);
                }
                return t;
            }

            /**
             * Arrange for the checked exception thrown by a replacement at the current cursor to be caught or declared.
             */
            private void requireHandled(String exception) {
                Cursor handler = findHandler(getCursor(), exception, acc);
                if (handler == null) {
                    // Excluded up front by `isFullySupported`
                    return;
                }
                if (handler.getValue() instanceof J.Try) {
                    if (!catches((J.Try) handler.getValue(), exception)) {
                        handler.putMessage(WIDEN_CATCH, true);
                    }
                } else {
                    handler.computeMessageIfAbsent(REQUIRED_THROWS, k -> new LinkedHashSet<String>()).add(exception);
                }
            }

            @Override
            public J visitNewClass(J.NewClass newClass, ExecutionContext ctx) {
                J j = super.visitNewClass(newClass, ctx);
                if (!(j instanceof J.NewClass)) {
                    return j;
                }
                J.NewClass nc = (J.NewClass) j;
                String subject;
                List<Object> parameters = new ArrayList<>();
                if (NO_ARG_CONSTRUCTOR.matches(nc)) {
                    subject = "\"CN=localhost\"";
                } else if (FQDN_CONSTRUCTOR.matches(nc)) {
                    Expression fqdn = nc.getArguments().get(0);
                    if (fqdn instanceof J.Literal && ((J.Literal) fqdn).getValue() instanceof String &&
                        ((J.Literal) fqdn).getValueSource() != null && ((J.Literal) fqdn).getValueSource().startsWith("\"")) {
                        // Reuse the original (escaped) source of the string literal
                        subject = "\"CN=" + ((J.Literal) fqdn).getValueSource().substring(1);
                    } else {
                        subject = "\"CN=\" + #{any(String)}";
                        parameters.add(fqdn);
                    }
                } else {
                    return nc;
                }
                // `CertificateBuilder.buildSelfSigned()` declares `throws Exception`
                requireHandled(EXCEPTION);
                maybeAddImport(CERTIFICATE_BUILDER);
                return JavaTemplate.builder("new CertificateBuilder().subject(" + subject + ").setIsCertificateAuthority(true).rsa2048().buildSelfSigned()")
                        .imports(CERTIFICATE_BUILDER)
                        .javaParser(JavaParser.fromJavaVersion().classpathFromResources(ctx, "netty-pkitesting"))
                        .build()
                        .apply(getCursor(), nc.getCoordinates().replace(), parameters.toArray());
            }

            @Override
            public @Nullable J visitMethodInvocation(J.MethodInvocation method, ExecutionContext ctx) {
                J j = super.visitMethodInvocation(method, ctx);
                if (!(j instanceof J.MethodInvocation)) {
                    return j;
                }
                J.MethodInvocation mi = (J.MethodInvocation) j;
                String replacement;
                if (CERT.matches(mi)) {
                    replacement = "getCertificate()";
                } else if (KEY.matches(mi)) {
                    replacement = "getKeyPair().getPrivate()";
                } else if (CERTIFICATE.matches(mi)) {
                    replacement = "toTempCertChainPem()";
                    requireHandled(IO_EXCEPTION);
                } else if (PRIVATE_KEY.matches(mi)) {
                    replacement = "toTempPrivateKeyPem()";
                    requireHandled(IO_EXCEPTION);
                } else if (DELETE.matches(mi)) {
                    // `X509Bundle` temporary files are deleted on JVM exit
                    return null;
                } else {
                    return mi;
                }
                return JavaTemplate.builder("#{any(" + X509_BUNDLE + ")}." + replacement)
                        .javaParser(JavaParser.fromJavaVersion().classpathFromResources(ctx, "netty-pkitesting"))
                        .build()
                        .apply(getCursor(), mi.getCoordinates().replace(), mi.getSelect());
            }
        });
    }

    /**
     * Find the {@link J.Try} or {@link J.MethodDeclaration} that will catch or declare the checked
     * {@code exception} (either {@code java.lang.Exception} or {@code java.io.IOException}) thrown at
     * {@code cursor} once it has been migrated, or {@code null} if it cannot be handled.
     *
     * @param acc when {@code null}, only accept a handler that already catches or declares the exception as is
     */
    private static @Nullable Cursor findHandler(Cursor cursor, String exception, @Nullable Accumulator acc) {
        Object child = cursor.getValue();
        for (Cursor c = cursor.getParentTreeCursor(); ; c = c.getParentTreeCursor()) {
            Object value = c.getValue();
            if (value instanceof J.Try) {
                J.Try t = (J.Try) value;
                // Only the body and resources are covered by the catch clauses
                if (!(child instanceof J.Try.Catch) && child != t.getFinally()) {
                    if (catches(t, exception) || acc != null && EXCEPTION.equals(exception) && isWidenable(t)) {
                        return c;
                    }
                    if (acc != null && EXCEPTION.equals(exception) && catchesCertificateException(t)) {
                        // Once the constructor no longer throws it, the `catch` would be unreachable
                        return null;
                    }
                }
            } else if (value instanceof J.MethodDeclaration) {
                J.MethodDeclaration m = (J.MethodDeclaration) value;
                return throwsCovers(m, exception) || acc != null && canChangeThrows(m, exception, acc) ? c : null;
            } else if (value instanceof J.Lambda || value instanceof J.ClassDeclaration ||
                       value instanceof JavaSourceFile ||
                       value instanceof J.NewClass && ((J.NewClass) value).getBody() == child) {
                // Lambdas and initializers cannot declare checked exceptions
                return null;
            }
            child = value;
        }
    }

    /**
     * Changing the {@code throws} clause must not break any caller. This excludes overriding methods,
     * constructors (which subclasses may invoke implicitly) and methods with a call site that does not
     * already catch or declare the exception.
     */
    private static boolean canChangeThrows(J.MethodDeclaration method, String exception, Accumulator acc) {
        JavaType.Method methodType = method.getMethodType();
        return methodType != null && !method.isConstructor() && !TypeUtils.isOverride(methodType) &&
               !acc.unhandled(exception).contains(methodKey(methodType));
    }

    /**
     * Deliberately ignores parameter types, so that overloads and generic signatures are matched conservatively.
     */
    private static String methodKey(JavaType.Method methodType) {
        return methodType.getDeclaringType().getFullyQualifiedName() + "#" + methodType.getName();
    }

    private static List<String> coveringTypes(String exception) {
        return EXCEPTION.equals(exception) ? asList(EXCEPTION, THROWABLE) : asList(exception, EXCEPTION, THROWABLE);
    }

    private static boolean catches(J.Try t, String exception) {
        return catchesAny(t, coveringTypes(exception));
    }

    private static boolean catchesCertificateException(J.Try t) {
        return catchesAny(t, asList(CERTIFICATE_EXCEPTION, GENERAL_SECURITY_EXCEPTION));
    }

    private static boolean catchesAny(J.Try t, List<String> exceptions) {
        for (J.Try.Catch c : t.getCatches()) {
            JavaType caught = c.getParameter().getTree().getType();
            List<JavaType> alternatives = caught instanceof JavaType.MultiCatch ?
                    ((JavaType.MultiCatch) caught).getThrowableTypes() : singletonList(caught);
            for (JavaType alternative : alternatives) {
                for (String exception : exceptions) {
                    if (TypeUtils.isOfClassType(alternative, exception)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * A trailing {@code catch (CertificateException e)} can be widened to {@code catch (Exception e)}
     * without making any other catch clause unreachable, without catching exceptions that used to propagate,
     * and without changing what the catch block itself does with the exception.
     */
    private static boolean isWidenable(J.Try t) {
        if (t.getCatches().isEmpty()) {
            return false;
        }
        J.Try.Catch last = t.getCatches().get(t.getCatches().size() - 1);
        JavaType caught = last.getParameter().getTree().getType();
        return (TypeUtils.isOfClassType(caught, CERTIFICATE_EXCEPTION) ||
                TypeUtils.isOfClassType(caught, GENERAL_SECURITY_EXCEPTION)) &&
               onlyCallsSelfSignedCertificate(t) && usesCaughtOnlyAsException(last);
    }

    /**
     * Any other call in the try block may throw an exception that a widened catch would start to swallow.
     */
    private static boolean onlyCallsSelfSignedCertificate(J.Try t) {
        AtomicBoolean only = new AtomicBoolean(true);
        JavaIsoVisitor<AtomicBoolean> visitor = new JavaIsoVisitor<AtomicBoolean>() {
            @Override
            public J.NewClass visitNewClass(J.NewClass newClass, AtomicBoolean only) {
                if (!NO_ARG_CONSTRUCTOR.matches(newClass) && !FQDN_CONSTRUCTOR.matches(newClass)) {
                    only.set(false);
                }
                return super.visitNewClass(newClass, only);
            }

            @Override
            public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, AtomicBoolean only) {
                if (!CERT.matches(method) && !KEY.matches(method) && !CERTIFICATE.matches(method) &&
                    !PRIVATE_KEY.matches(method) && !DELETE.matches(method)) {
                    only.set(false);
                }
                return super.visitMethodInvocation(method, only);
            }
        };
        if (t.getResources() != null) {
            for (J.Try.Resource resource : t.getResources()) {
                visitor.visit(resource, only);
            }
        }
        visitor.visit(t.getBody(), only);
        return only.get();
    }

    /**
     * Once widened, the caught variable is an {@code Exception}: rethrowing it would require {@code throws Exception},
     * and passing it where a more specific type is expected would no longer compile.
     */
    private static boolean usesCaughtOnlyAsException(J.Try.Catch c) {
        J.VariableDeclarations.NamedVariable caught = c.getParameter().getTree().getVariables().get(0);
        AtomicBoolean safe = new AtomicBoolean(true);
        new JavaIsoVisitor<AtomicBoolean>() {
            @Override
            public J.Identifier visitIdentifier(J.Identifier identifier, AtomicBoolean safe) {
                if (refersTo(identifier, caught) && !isUsableAsException(identifier, getCursor().getParentTreeCursor().getValue())) {
                    safe.set(false);
                }
                return super.visitIdentifier(identifier, safe);
            }
        }.visit(c.getBody(), safe);
        return safe.get();
    }

    private static boolean isUsableAsException(J.Identifier identifier, Object parent) {
        if (parent instanceof J.MethodInvocation) {
            J.MethodInvocation mi = (J.MethodInvocation) parent;
            return mi.getSelect() == identifier || acceptsException(mi.getMethodType(), indexOf(mi.getArguments(), identifier));
        } else if (parent instanceof J.NewClass) {
            J.NewClass nc = (J.NewClass) parent;
            return acceptsException(nc.getConstructorType(), indexOf(nc.getArguments(), identifier));
        }
        // String concatenation
        return parent instanceof J.Binary;
    }

    private static boolean acceptsException(JavaType.@Nullable Method methodType, int argument) {
        if (methodType == null || argument < 0 || methodType.getParameterTypes().isEmpty()) {
            return false;
        }
        List<JavaType> parameterTypes = methodType.getParameterTypes();
        JavaType parameterType = parameterTypes.get(Math.min(argument, parameterTypes.size() - 1));
        if (argument >= parameterTypes.size() - 1 && parameterType instanceof JavaType.Array) {
            // Varargs
            parameterType = ((JavaType.Array) parameterType).getElemType();
        }
        return TypeUtils.isOfClassType(parameterType, THROWABLE) ||
               TypeUtils.isOfClassType(parameterType, EXCEPTION) ||
               TypeUtils.isOfClassType(parameterType, OBJECT);
    }

    private static int indexOf(List<Expression> arguments, J.Identifier identifier) {
        for (int i = 0; i < arguments.size(); i++) {
            if (arguments.get(i) == identifier) {
                return i;
            }
        }
        return -1;
    }

    private static boolean refersTo(J.Identifier identifier, J.VariableDeclarations.NamedVariable variable) {
        return identifier.getFieldType() != null && identifier.getSimpleName().equals(variable.getSimpleName()) &&
               TypeUtils.isOfType(identifier.getFieldType().getType(), variable.getType());
    }

    private static boolean throwsCovers(J.MethodDeclaration method, String exception) {
        if (method.getThrows() != null) {
            for (NameTree t : method.getThrows()) {
                for (String covering : coveringTypes(exception)) {
                    if (TypeUtils.isOfClassType(t.getType(), covering)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Widen a declared {@code CertificateException} or {@code GeneralSecurityException} to {@code Exception},
     * or otherwise add {@code Exception} to the {@code throws} clause.
     */
    private static J.MethodDeclaration addThrowsException(J.MethodDeclaration method) {
        if (method.getThrows() != null) {
            AtomicBoolean replaced = new AtomicBoolean();
            List<NameTree> newThrows = ListUtils.map(method.getThrows(), t -> {
                if (TypeUtils.isOfClassType(t.getType(), CERTIFICATE_EXCEPTION) ||
                    TypeUtils.isOfClassType(t.getType(), GENERAL_SECURITY_EXCEPTION)) {
                    return replaced.getAndSet(true) ? null : newIdentifier(t.getPrefix(), "Exception", EXCEPTION);
                }
                return t;
            });
            if (replaced.get()) {
                return method.withThrows(newThrows);
            }
        }
        return addThrows(method, newIdentifier(Space.SINGLE_SPACE, "Exception", EXCEPTION));
    }

    private static J.MethodDeclaration addThrows(J.MethodDeclaration method, NameTree exception) {
        if (method.getThrows() == null) {
            return method.getPadding().withThrows(JContainer.build(Space.SINGLE_SPACE,
                    singletonList(JRightPadded.build(exception)), Markers.EMPTY));
        }
        return method.withThrows(ListUtils.concat(method.getThrows(), exception));
    }

    private static J.Identifier newIdentifier(Space prefix, String simpleName, String fullyQualifiedName) {
        return new J.Identifier(Tree.randomId(), prefix, Markers.EMPTY, emptyList(), simpleName,
                JavaType.ShallowClass.build(fullyQualifiedName), null);
    }

    /**
     * Only migrate a source file when every use of {@code SelfSignedCertificate} has a known replacement,
     * so we never leave behind a mix of {@code SelfSignedCertificate} and {@code X509Bundle} that does not compile.
     */
    private static boolean isFullySupported(J.CompilationUnit cu, Accumulator acc) {
        Set<String> declaredTypes = new HashSet<>();
        new JavaIsoVisitor<Set<String>>() {
            @Override
            public J.ClassDeclaration visitClassDeclaration(J.ClassDeclaration classDecl, Set<String> declaredTypes) {
                if (classDecl.getType() != null) {
                    declaredTypes.add(classDecl.getType().getFullyQualifiedName());
                }
                return super.visitClassDeclaration(classDecl, declaredTypes);
            }
        }.visit(cu, declaredTypes);

        AtomicBoolean supported = new AtomicBoolean(true);
        new JavaIsoVisitor<AtomicBoolean>() {
            @Override
            public J.NewClass visitNewClass(J.NewClass newClass, AtomicBoolean supported) {
                if (NO_ARG_CONSTRUCTOR.matches(newClass) || FQDN_CONSTRUCTOR.matches(newClass)) {
                    if (findHandler(getCursor(), EXCEPTION, acc) == null) {
                        supported.set(false);
                    }
                } else if (TypeUtils.isOfClassType(newClass.getType(), SELF_SIGNED_CERTIFICATE) ||
                           passesToExternalApi(newClass.getConstructorType())) {
                    supported.set(false);
                }
                return super.visitNewClass(newClass, supported);
            }

            @Override
            public J.MethodInvocation visitMethodInvocation(J.MethodInvocation method, AtomicBoolean supported) {
                JavaType.Method methodType = method.getMethodType();
                if (methodType != null) {
                    if (TypeUtils.isOfClassType(methodType.getDeclaringType(), SELF_SIGNED_CERTIFICATE)) {
                        boolean deleteStatement = DELETE.matches(method) && getCursor().getParentTreeCursor().getValue() instanceof J.Block;
                        if (CERTIFICATE.matches(method) || PRIVATE_KEY.matches(method)) {
                            if (findHandler(getCursor(), IO_EXCEPTION, acc) == null) {
                                supported.set(false);
                            }
                        } else if (!deleteStatement && !CERT.matches(method) && !KEY.matches(method)) {
                            supported.set(false);
                        }
                    } else if (passesToExternalApi(methodType)) {
                        supported.set(false);
                    }
                }
                return super.visitMethodInvocation(method, supported);
            }

            @Override
            public J.MemberReference visitMemberReference(J.MemberReference memberRef, AtomicBoolean supported) {
                JavaType.Method methodType = memberRef.getMethodType();
                if (methodType != null && TypeUtils.isOfClassType(methodType.getDeclaringType(), SELF_SIGNED_CERTIFICATE)) {
                    supported.set(false);
                }
                return super.visitMemberReference(memberRef, supported);
            }

            /**
             * Passing a {@code SelfSignedCertificate} to an external method or constructor would no longer compile.
             */
            private boolean passesToExternalApi(JavaType.@Nullable Method methodType) {
                if (methodType == null || declaredTypes.contains(methodType.getDeclaringType().getFullyQualifiedName())) {
                    return false;
                }
                for (JavaType parameterType : methodType.getParameterTypes()) {
                    if (TypeUtils.isOfClassType(parameterType, SELF_SIGNED_CERTIFICATE)) {
                        return true;
                    }
                }
                return false;
            }
        }.visit(cu, supported);
        return supported.get();
    }
}
