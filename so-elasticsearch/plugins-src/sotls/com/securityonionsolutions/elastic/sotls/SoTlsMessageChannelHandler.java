package com.securityonionsolutions.elastic.sotls;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.AdaptiveRecvByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.FixedRecvByteBufAllocator;
import io.netty.channel.RecvByteBufAllocator;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.FutureListener;
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

public class SoTlsMessageChannelHandler extends ChannelDuplexHandler {
  public SoTlsMessageChannelHandler() {
    super();
  }

  public void channelActive(ChannelHandlerContext ctx) throws Exception {
    SslHandler sslHandler = ctx.pipeline().get(SslHandler.class);
    final Future<Channel> handshakeFuture = sslHandler.handshakeFuture();
    handshakeFuture.addListener(new FutureListener<Channel>() {
      @Override
      public void operationComplete(Future<Channel> future) throws Exception {
        if (future.isSuccess()) {
        } else {
          future.get().close();                    
        }
      }
    });
  }
}