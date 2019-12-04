package org.tinyradius.server;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import io.netty.util.Timeout;
import io.netty.util.Timer;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tinyradius.packet.PacketEncoder;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.server.handler.RequestHandler;
import org.tinyradius.util.RadiusException;

import java.net.InetSocketAddress;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * SimpleChannelInboundHandler implementation that converts between RadiusPackets
 * and DatagramPackets. Acts as an adapter so RequestHandlers dont have to be
 * concerned with {@link DatagramPacket}, and can work with {@link RadiusPacket}
 * directly.
 *
 * @param <T> RadiusPacket types that this Channel can accept
 */
public class HandlerAdapter<T extends RadiusPacket, S extends SecretProvider> extends SimpleChannelInboundHandler<DatagramPacket> {

    private static final Logger logger = LoggerFactory.getLogger(HandlerAdapter.class);

    private final PacketEncoder packetEncoder;
    private final RequestHandler<T, S> requestHandler;
    private final Timer timer;
    private final S secretProvider;
    private final Class<T> packetClass;

    /**
     * @param packetEncoder  for encoding/decoding RadiusPackets
     * @param requestHandler handle requests
     * @param timer          handle timeouts if requests take too long to be processed
     * @param secretProvider lookup sharedSecret given remote address
     * @param packetClass    restrict RadiusPacket subtypes that can be processed by handler, otherwise will be dropped.
     *                       If all types of RadiusPackets are allowed, use {@link RadiusPacket}
     */
    public HandlerAdapter(PacketEncoder packetEncoder, RequestHandler<T, S> requestHandler, Timer timer, S secretProvider, Class<T> packetClass) {
        this.packetEncoder = packetEncoder;
        this.requestHandler = requestHandler;
        this.timer = timer;
        this.secretProvider = secretProvider;
        this.packetClass = packetClass;
    }

    public void channelRead0(ChannelHandlerContext ctx, DatagramPacket requestPacket) {
        try {
            handleRequest(ctx.channel(), requestPacket).addListener((Future<DatagramPacket> f) -> {
                // don't respond if processing/authenticator error
                if (f.isSuccess()) {
                    DatagramPacket responsePacket = f.getNow();
                    if (responsePacket != null) {
                        logger.info("Request handled, sending response to {}", responsePacket.recipient());
                        ctx.writeAndFlush(responsePacket);
                    } else {
                        logger.info("Request handled, nothing to respond");
                    }
                } else {
                    logger.error("Request dropped, exception while handling request", f.cause());
                }
            });
        } catch (RadiusException e) {
            logger.info("Request dropped, issue with packet or upstream: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Request dropped, exception while handling request", e);
        }
    }

    /**
     * Processes DatagramPacket. This does not swallow exceptions.
     *
     * @param channel        socket on which request was received
     * @param datagramPacket datagram received
     * @return Future that completes when request is handled. Can contain DatagramPacket response
     * @throws RadiusException malformed packet
     */
    protected Future<DatagramPacket> handleRequest(Channel channel, DatagramPacket datagramPacket) throws RadiusException {
        InetSocketAddress localAddress = datagramPacket.recipient();
        InetSocketAddress remoteAddress = datagramPacket.sender();

        String secret = secretProvider.getSharedSecret(remoteAddress);
        if (secret == null)
            throw new RadiusException("Ignoring request from unknown client " + remoteAddress +
                    ", shared secret lookup failed (local address " + localAddress + ")");

        // parse packet
        RadiusPacket request = packetEncoder.fromDatagram(datagramPacket, secret);
        logger.info("Received packet from {} on local address {} - {}", remoteAddress, localAddress, request);

        // check channelHandler packet type restrictions
        if (!packetClass.isInstance(request))
            throw new RadiusException("Handler only accepts " + packetClass.getSimpleName() + ", actual packet " + request.getClass().getSimpleName());

        final byte[] requestAuth = request.getAuthenticator(); // save ref in case request is mutated

        final Promise<RadiusPacket> handlerResult = requestHandler.handlePacket(channel, packetClass.cast(request), remoteAddress, secretProvider);

        // so futures don't stay in memory forever if never completed
        Timeout timeout = timer.newTimeout(t -> handlerResult.tryFailure(
                new RadiusException("Request handler timed out")), 10, SECONDS);

        final Promise<DatagramPacket> datagramResult = channel.eventLoop().newPromise();

        handlerResult.addListener((Future<RadiusPacket> f) -> {
            timeout.cancel();

            if (f.isSuccess()) {
                final RadiusPacket response = f.getNow();
                if (response != null) {
                    logger.debug("Encoding response for {}", remoteAddress);
                    datagramResult.trySuccess(packetEncoder.toDatagram(
                            response.encodeResponse(secret, requestAuth), remoteAddress, localAddress));
                } else {
                    datagramResult.trySuccess(null);
                }
            } else {
                datagramResult.tryFailure(f.cause());
            }
        });

        return datagramResult;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "(" + requestHandler.toString() + ")";
    }
}
