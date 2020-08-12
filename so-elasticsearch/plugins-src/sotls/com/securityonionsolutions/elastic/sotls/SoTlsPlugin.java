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
import org.elasticsearch.common.settings.Settings.Builder;
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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Plugin created by following Elastic's published plugin documentation and examples.
 * Specifically:
 *   https://www.elastic.co/guide/en/elasticsearch/plugins/7.8/plugin-authors.html
 *   https://github.com/elastic/elasticsearch/tree/master/plugins/examples/custom-settings
 *
 * And from a 2017 blog post by Adam Vanderbush about securing Elasticsearch via a TLS plugin:
 *   https://qbox.io/blog/elasticsearch-netty-secure-ssl-tls-implementation
 *
 * By default both transport and HTTP encryption is disabled. A sotls.yml file should exist 
 * along side of the standard elasticsearch.yml file. Inside of the sotls.yml the keystore,
 * truststore, ciphers, protocols, etc. can be configured and enabled.
 */
public class SoTlsPlugin extends Plugin implements NetworkPlugin {
  public static final String TRANSPORT_NAME = "sotls";
  public static final String HTTP_TRANSPORT_NAME = "sotls";
  private final SoTlsConfig config;
  private final SslEngineFactory sslFactory;

  public SoTlsPlugin(final Settings settings, final Path configPath) {
    this.config = new SoTlsConfig(new Environment(settings, configPath));
    this.sslFactory = SslEngineFactory.getInstance(this.config);
  }

  @Override
  public List<Setting<?>> getSettings() {
    return this.config.getSettings();
  }

  @Override
  public Settings additionalSettings() {
    Builder builder = Settings.builder();
    if (this.config.isHttpEncrypted()) {
      builder.put(NetworkModule.HTTP_TYPE_SETTING.getKey(), HTTP_TRANSPORT_NAME);
    }
    if (this.config.isTransportEncrypted()) {
      builder.put(NetworkModule.TRANSPORT_TYPE_SETTING.getKey(), TRANSPORT_NAME);
    }
    return builder.build();
  }

  @Override
  public Map<String, Supplier<Transport>> getTransports(Settings settings, ThreadPool threadPool, PageCacheRecycler pageCacheRecycler,
                                                        CircuitBreakerService circuitBreakerService,
                                                        NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {
    if (this.config.isTransportEncrypted()) {
      return Collections.singletonMap(TRANSPORT_NAME, 
        () -> new SoTlsNettyTransport(this.sslFactory, settings, Version.CURRENT, threadPool,
          networkService, pageCacheRecycler, namedWriteableRegistry, circuitBreakerService));
    } else {
      return Collections.emptyMap();
    }
  }

  @Override
  public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
                                                                      PageCacheRecycler pageCacheRecycler,
                                                                      CircuitBreakerService circuitBreakerService,
                                                                      NamedXContentRegistry xContentRegistry,
                                                                      NetworkService networkService,
                                                                      HttpServerTransport.Dispatcher dispatcher,
                                                                      ClusterSettings clusterSettings) {
    if (this.config.isHttpEncrypted()) {
      return Collections.singletonMap(HTTP_TRANSPORT_NAME,
        () -> new SoTlsNettyHttpServerTransport(this.sslFactory, settings, networkService, bigArrays, threadPool, xContentRegistry, dispatcher,
          clusterSettings));
    } else {
      return Collections.emptyMap();
    }
  }
}