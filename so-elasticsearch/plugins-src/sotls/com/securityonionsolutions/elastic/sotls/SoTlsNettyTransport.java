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

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelInitializer;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.lease.Releasables;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.PageCacheRecycler;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.netty4.Netty4Transport;
import org.elasticsearch.transport.SharedGroupFactory;

public class SoTlsNettyTransport extends Netty4Transport {
  private static final Logger logger = LogManager.getLogger(SoTlsNettyTransport.class);

  private final SslEngineFactory sslFactory;

  public SoTlsNettyTransport(SslEngineFactory sslFactory, Settings settings, Version version, ThreadPool threadPool, NetworkService networkService,
                           PageCacheRecycler pageCacheRecycler, NamedWriteableRegistry namedWriteableRegistry,
                           CircuitBreakerService circuitBreakerService, SharedGroupFactory groupFactory) {
    super(settings, version, threadPool, networkService, pageCacheRecycler, namedWriteableRegistry, circuitBreakerService, groupFactory);
    this.sslFactory = sslFactory;
  }

  protected ChannelHandler getServerChannelInitializer(String name) {
      return new SoTlsServerChannelInitializer(name);
  }

  protected ChannelHandler getClientChannelInitializer(DiscoveryNode node) {
      return new SoTlsClientChannelInitializer();
  }

  protected class SoTlsClientChannelInitializer extends ClientChannelInitializer {
    @Override
    protected void initChannel(Channel ch) throws Exception {
      super.initChannel(ch);
      ch.pipeline().addFirst(SoTlsPlugin.TRANSPORT_NAME, new SslHandler(sslFactory.create(true)));
      ch.pipeline().addAfter(SoTlsPlugin.TRANSPORT_NAME, "handshake", new SoTlsMessageChannelHandler());
      logger.debug("Injected SSL handlers into transport client pipeline");
    }
  }

  protected class SoTlsServerChannelInitializer extends ServerChannelInitializer {
    protected SoTlsServerChannelInitializer(String name) {
      super(name);
      logger.info("Enabled TLS on transport server");
    }

    @Override
    protected void initChannel(Channel ch) throws Exception {
      super.initChannel(ch);
      ch.pipeline().addFirst(SoTlsPlugin.TRANSPORT_NAME, new SslHandler(sslFactory.create(false)));
      logger.debug("Injected SSL handler into transport server pipeline");
    }
  }
}