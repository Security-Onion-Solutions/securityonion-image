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
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.http.HttpHandlingSettings;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.threadpool.ThreadPool;

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
