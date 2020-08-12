package com.securityonionsolutions.elastic.sotls;

import io.netty.bootstrap.ServerBootstrap;
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
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.http.HttpContentCompressor;
import io.netty.handler.codec.http.HttpContentDecompressor;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.timeout.ReadTimeoutException;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.util.AttributeKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.core.internal.net.NetUtils;
import org.elasticsearch.http.AbstractHttpServerTransport;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.http.HttpHandlingSettings;
import org.elasticsearch.http.HttpReadTimeoutException;
import org.elasticsearch.http.HttpServerChannel;
import org.elasticsearch.http.netty4.cors.Netty4CorsHandler;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.NettyAllocator;
import org.elasticsearch.transport.netty4.Netty4Utils;

import java.net.InetSocketAddress;
import java.net.SocketOption;
import java.util.concurrent.TimeUnit;

public class SoTlsNettyHttpServerTransport extends Netty4HttpServerTransport {
  private static final Logger logger = LogManager.getLogger(SoTlsNettyHttpServerTransport.class);
  private final SslEngineFactory sslFactory;

  public SoTlsNettyHttpServerTransport(SslEngineFactory sslFactory, Settings settings, NetworkService networkService, BigArrays bigArrays, ThreadPool threadPool,
                                     NamedXContentRegistry xContentRegistry, Dispatcher dispatcher, ClusterSettings clusterSettings) {
    super(settings, networkService, bigArrays, threadPool, xContentRegistry, dispatcher, clusterSettings);
    this.sslFactory = sslFactory;
  }

  public ChannelHandler configureServerChannelHandler() {
    return new SoTlsHttpChannelHandler(this, handlingSettings);
  }

  public SslEngineFactory getSslFactory() {
    return this.sslFactory;
  }

  protected static class SoTlsHttpChannelHandler extends HttpChannelHandler {
    private final SoTlsNettyHttpServerTransport transport;

    protected SoTlsHttpChannelHandler(final SoTlsNettyHttpServerTransport transport, final HttpHandlingSettings handlingSettings) {
      super(transport, handlingSettings);
      this.transport = transport;
      logger.info("Enabled TLS on HTTP server");
    }

    @Override
    protected void initChannel(Channel ch) throws Exception {
      super.initChannel(ch);
      ch.pipeline().addFirst(SoTlsPlugin.HTTP_TRANSPORT_NAME, new SslHandler(this.transport.getSslFactory().create(false)));
      logger.debug("Injected SSL handler into HTTP server pipeline");
    }
  }
}
