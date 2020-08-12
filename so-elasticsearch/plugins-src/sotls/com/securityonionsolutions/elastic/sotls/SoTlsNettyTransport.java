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

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.AdaptiveRecvByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.FixedRecvByteBufAllocator;
import io.netty.channel.RecvByteBufAllocator;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioChannelOption;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.Future;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.lease.Releasables;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.util.PageCacheRecycler;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.core.internal.net.NetUtils;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.NettyAllocator;
import org.elasticsearch.transport.TcpTransport;
import org.elasticsearch.transport.TransportSettings;
import org.elasticsearch.transport.netty4.Netty4Transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketOption;
import java.util.Map;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

public class SoTlsNettyTransport extends Netty4Transport {
  private static final Logger logger = LogManager.getLogger(SoTlsNettyTransport.class);

  private final SslEngineFactory sslFactory;

  public SoTlsNettyTransport(SslEngineFactory sslFactory, Settings settings, Version version, ThreadPool threadPool, NetworkService networkService,
                           PageCacheRecycler pageCacheRecycler, NamedWriteableRegistry namedWriteableRegistry,
                           CircuitBreakerService circuitBreakerService) {
    super(settings, version, threadPool, networkService, pageCacheRecycler, namedWriteableRegistry, circuitBreakerService);
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