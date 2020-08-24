//  Copyright 2020 Security Onion Solutions, LLC
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
// 
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
// 
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

package com.securityonionsolutions.elastic.sotls;

import java.io.FileInputStream;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivilegedAction;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;

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