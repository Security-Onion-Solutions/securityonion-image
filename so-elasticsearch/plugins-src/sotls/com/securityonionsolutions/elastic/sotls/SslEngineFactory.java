package com.securityonionsolutions.elastic.sotls;

import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.security.cert.CertificateException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;

import org.elasticsearch.Version;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.PageCacheRecycler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.netty4.Netty4Transport;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public class SslEngineFactory {
  private static final Object instanceLock = new Object();
  private static SslEngineFactory instance;

  public static SslEngineFactory getInstance(SoTlsConfig config) {
    if (instance == null) {
      synchronized(instanceLock) {
        if (instance == null) {
          instance = new SslEngineFactory(config);
        }
      }
    }
    return instance;
  }

  private final SoTlsConfig config;
  private final Object sslContextLock = new Object();
  private SSLContext sslContext;

  protected SslEngineFactory(final SoTlsConfig config) {
    this.config = config;
  }

  protected KeyStore createKeyStore(String path, char[] password) throws Exception {
    KeyStore keystore = KeyStore.getInstance("jks");
    Exception loadException = AccessController.doPrivileged(new PrivilegedAction<Exception>() {
      public Exception run() {
        try {
          FileInputStream keystoreInputStream = new FileInputStream(path);
          keystore.load(keystoreInputStream, password);
        } catch (Exception e) {
          return e;
        }
        return null;
      }
    });
    
    if (loadException != null) throw loadException;

    return keystore;
  }

  protected KeyManagerFactory createKeyManagerFactory() throws Exception {
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(this.config.getKeyStoreAlgorithm());
    char[] password = this.config.getKeyStorePassword().toCharArray();
    keyManagerFactory.init(createKeyStore(this.config.getKeyStorePath(), password), password);
    return keyManagerFactory;
  }

  protected TrustManagerFactory createTrustManagerFactory() throws Exception {
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(this.config.getTrustStoreAlgorithm());
    char[] password = this.config.getTrustStorePassword().toCharArray();
    trustManagerFactory.init(createKeyStore(this.config.getTrustStorePath(), password));
    return trustManagerFactory;
  }

  protected SSLContext createSslContext() throws Exception {
    if (this.sslContext == null) {
      synchronized(this.sslContextLock) {
        if (this.sslContext == null) {
          this.sslContext = SSLContext.getInstance("tls");
          this.sslContext.init(createKeyManagerFactory().getKeyManagers(), createTrustManagerFactory().getTrustManagers(), null);
        }
      }
    }
    return this.sslContext;
  }

  public SSLEngine create(boolean clientMode) throws Exception {
    SSLEngine sslEngine = this.createSslContext().createSSLEngine();
    sslEngine.setEnabledProtocols(this.config.getEnabledProtocols());
    sslEngine.setEnabledCipherSuites(this.config.getEnabledCiphers());
    sslEngine.setUseClientMode(clientMode);
    return sslEngine;
  }
}