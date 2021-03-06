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
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.FutureListener;

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