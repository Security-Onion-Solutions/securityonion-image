package com.securityonionsolutions.elastic.sotls;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.function.Function;
import java.util.List;

public class SoTlsConfig {
  static final Setting<String> KEY_STORE_PATH = Setting.simpleString("keystore.path", Property.NodeScope);
  static final Setting<String> KEY_STORE_PASSWORD = Setting.simpleString("keystore.password", Property.NodeScope);
  static final Setting<String> KEY_STORE_ALGORITHM = Setting.simpleString("keystore.algorithm", Property.NodeScope);
  static final Setting<String> TRUST_STORE_PATH = Setting.simpleString("truststore.path", Property.NodeScope);
  static final Setting<String> TRUST_STORE_PASSWORD = Setting.simpleString("truststore.password", Property.NodeScope);
  static final Setting<String> TRUST_STORE_ALGORITHM = Setting.simpleString("truststore.algorithm", Property.NodeScope);
  static final Setting<List<String>> PROTOCOLS = Setting.listSetting("protocols", Collections.emptyList(), Function.identity(), Property.NodeScope);
  static final Setting<List<String>> CIPHERS = Setting.listSetting("ciphers", Collections.emptyList(), Function.identity(), Property.NodeScope);
  static final Setting<Boolean> TRANSPORT_ENCRYPTED = Setting.boolSetting("transport.encrypted", false, Property.NodeScope);
  static final Setting<Boolean> HTTP_ENCRYPTED = Setting.boolSetting("http.encrypted", false, Property.NodeScope);

  private final String keyStorePath;
  private final String keyStorePassword;
  private final String keyStoreAlgorithm;
  private final String trustStorePath;
  private final String trustStorePassword;
  private final String trustStoreAlgorithm;
  private final List<String> protocols;
  private final List<String> ciphers;
  private final Boolean transportEncrypted;
  private final Boolean httpEncrypted;

  public SoTlsConfig(final Environment environment) {
    final Path configDir = environment.configFile();
    final Path customSettingsYamlFile = configDir.resolve("sotls.yml");
    final Settings customSettings;
    try {
      customSettings = Settings.builder().loadFromPath(customSettingsYamlFile).build();
      assert customSettings != null;
    } catch (IOException e) {
      throw new ElasticsearchException("Failed to load SoTls plugin settings", e);
    }

    this.keyStorePath = KEY_STORE_PATH.get(customSettings);
    this.keyStorePassword = KEY_STORE_PASSWORD.get(customSettings);
    this.keyStoreAlgorithm = KEY_STORE_ALGORITHM.get(customSettings);
    this.trustStorePath = TRUST_STORE_PATH.get(customSettings);
    this.trustStorePassword = TRUST_STORE_PASSWORD.get(customSettings);
    this.trustStoreAlgorithm = TRUST_STORE_ALGORITHM.get(customSettings);
    this.protocols = PROTOCOLS.get(customSettings);
    this.ciphers = CIPHERS.get(customSettings);
    this.transportEncrypted = TRANSPORT_ENCRYPTED.get(customSettings);
    this.httpEncrypted = HTTP_ENCRYPTED.get(customSettings);
  }

  public List<Setting<?>> getSettings() {
    return Arrays.asList(
      SoTlsConfig.KEY_STORE_PATH,
      SoTlsConfig.KEY_STORE_PASSWORD,
      SoTlsConfig.KEY_STORE_ALGORITHM,
      SoTlsConfig.TRUST_STORE_PATH,
      SoTlsConfig.TRUST_STORE_PASSWORD,
      SoTlsConfig.TRUST_STORE_ALGORITHM,
      SoTlsConfig.PROTOCOLS,
      SoTlsConfig.CIPHERS,
      SoTlsConfig.TRANSPORT_ENCRYPTED,
      SoTlsConfig.HTTP_ENCRYPTED
    );
  }

  public String getKeyStorePath() {
    return keyStorePath;
  }

  public String getKeyStorePassword() {
    return keyStorePassword;
  }

  public String getKeyStoreAlgorithm() {
    return keyStoreAlgorithm;
  }

  public String getTrustStorePath() {
    return trustStorePath;
  }

  public String getTrustStorePassword() {
    return trustStorePassword;
  }

  public String getTrustStoreAlgorithm() {
    return trustStoreAlgorithm;
  }

  public String[] getEnabledProtocols() {
    return protocols.toArray(new String[0]);
  }

  public String[] getEnabledCiphers() {
    return ciphers.toArray(new String[0]);
  }

  public boolean isTransportEncrypted() {
    return transportEncrypted;
  }

  public boolean isHttpEncrypted() {
    return httpEncrypted;
  }
}