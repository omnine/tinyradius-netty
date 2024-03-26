package org.tinyradius.io;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.util.HashedWheelTimer;
import io.netty.util.Timer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.tinyradius.core.RadiusPacketException;
import org.tinyradius.core.dictionary.DefaultDictionary;
import org.tinyradius.core.dictionary.Dictionary;
import org.tinyradius.core.packet.PacketType;
import org.tinyradius.core.packet.request.*;
import org.tinyradius.core.packet.response.RadiusResponse;
import org.tinyradius.io.client.RadiusClient;
import org.tinyradius.io.client.handler.BlacklistHandler;
import org.tinyradius.io.client.handler.ClientDatagramCodec;
import org.tinyradius.io.client.handler.PromiseAdapter;
import org.tinyradius.io.client.timeout.FixedTimeoutHandler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.util.Collections;

import static org.tinyradius.core.packet.PacketType.ACCESS_REQUEST;



/**
 * TestClient shows how to send Radius Access-Request and Accounting-Request packets.
 */
public class TestClient {

    private static final Logger logger = LogManager.getLogger();

    /**
     * Radius command line client.
     *
     * @param args [host, sharedSecret, username, password]
     */
    public static void main(String[] args) throws RadiusPacketException {
        if (args.length != 5) {
            System.out.println("Usage: TestClient [hostName] [sharedSecret] [userName] [password] [protocol]");
            System.out.println("protocol: 1=PAP, 2=MSCHAPv2 then OTP, 3=MSCHAPv2 then MSCHAPv2");

            return;
        }

        final String host = args[0];
        final String shared = args[1];
        final String user = args[2];
        final String pass = args[3];
        final String protocol = args[4];

        String[] userInput={"123456","1234"};
        // Enter data using BufferReader
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in));

        // Reading data using readLine
        System.out.println("Please enter PIN:");
        try {
            userInput[1] = reader.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Reading data using readLine
        System.out.println("Please enter OTP code:");
        try {
            userInput[0] = reader.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Printing the read line
//        System.out.println(otpCode);

        final NioEventLoopGroup eventLoopGroup = new NioEventLoopGroup(4);

        final Dictionary dictionary = DefaultDictionary.INSTANCE;
        final Timer timer = new HashedWheelTimer();

        final Bootstrap bootstrap = new Bootstrap().group(eventLoopGroup).channel(NioDatagramChannel.class);

        final RadiusClient rc = new RadiusClient(
                bootstrap, new InetSocketAddress(0), new FixedTimeoutHandler(timer), new ChannelInitializer<DatagramChannel>() {
            @Override
            protected void initChannel(DatagramChannel ch) {
                ch.pipeline().addLast(
                        new ClientDatagramCodec(dictionary),
                        new PromiseAdapter(),
                        new BlacklistHandler(60_000, 3));
            }
        });

        final RadiusEndpoint authEndpoint = new RadiusEndpoint(new InetSocketAddress(host, 1812), shared);
//        final RadiusEndpoint acctEndpoint = new RadiusEndpoint(new InetSocketAddress(host, 1813), shared);


        switch (protocol) {
            case "1":
                System.out.println("PAP on both steps.");
                tryPAP(rc, dictionary, authEndpoint, user, pass, userInput);
                break;
            case "2":
                System.out.println("MSCHAPv2 on the first step, but PAP on the second step.");
                tryMSCHAPv2Half(rc, dictionary, authEndpoint, user, pass, userInput);
                break;
            default:
                System.out.println("MSCHAPv2 on both steps.");
                tryMSCHAPv2(rc, dictionary, authEndpoint, user, pass, userInput);
                break;
        }

/*
        // 1. Send Access-Request
        final AccessRequest ar = (AccessRequest)
                ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte) 1, null, Collections.emptyList()))
                .withMSCHapv2Password(user, pass)
                .addAttribute("User-Name", user)
                .addAttribute("NAS-IP-Address", "192.168.222.1");
//                .addAttribute("NAS-Identifier", "this.is.my.nas-identifier.de")
//                .addAttribute("Service-Type", "Login-User");
//                .addAttribute("WISPr-Redirection-URL", "https://www.sourceforge.net/")
//                .addAttribute("WISPr-Location-ID", "net.sourceforge.ap1");




//        logger.info("Packet before it is sent\n" + ar + "\n");
        RadiusResponse response = rc.communicate(ar, authEndpoint).syncUninterruptibly().getNow();
//        logger.info("Packet after it was sent\n" + ar + "\n");
        logger.info("Response\n" + response + "\n");

        if (response.getType() == PacketType.ACCESS_CHALLENGE) { //challenge packet
            // State Attribute, we have to pass back to radius server for 2nd step login
            byte[] state = response.getAttribute(24).get().getValue();

            final AccessRequest ar2 = (AccessRequest)
                    ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte) 1, null, Collections.emptyList()))
                            .withMSCHapv2Password(user, otpCode)
                            .addAttribute("User-Name", user)
                            .addAttribute(dictionary.createAttribute(-1, 24, state))
                            .addAttribute("NAS-IP-Address", "192.168.222.1");

            RadiusResponse response2 = rc.communicate(ar2, authEndpoint).syncUninterruptibly().getNow();
            logger.info("Response\n" + response2 + "\n");


            // 1. Send Access-Request
            final AccessRequestPap ar2 = (AccessRequestPap)
                    ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte) 1, null, Collections.emptyList()))
                            .withPapPassword(otpCode)
                            .addAttribute("User-Name", user)
                            .addAttribute(dictionary.createAttribute(-1, 24, state))
                            .addAttribute("NAS-IP-Address", "192.168.222.1");
            RadiusResponse response2 = rc.communicate(ar2, authEndpoint).syncUninterruptibly().getNow();
            logger.info("Response\n" + response2 + "\n");

            if(response2.getType() == PacketType.ACCESS_ACCEPT) {
                System.out.println("Authentication is successful.");
            }
            else {
                System.out.println("Access Denied!");
            }
        }
        else {
            if(response.getType() == PacketType.ACCESS_ACCEPT) {
                System.out.println("Authentication is successful.");
            }
            else {
                System.out.println("Access Denied!");
            }
        }


        // 2. Send Accounting-Request

        final AccountingRequest acc = (AccountingRequest) RadiusRequest.create(dictionary, ACCOUNTING_REQUEST, (byte) 2, null, new ArrayList<>())
                .addAttribute("User-Name", "username")
                .addAttribute("Acct-Status-Type", "1")
                .addAttribute("Acct-Session-Id", "1234567890")
                .addAttribute("NAS-Identifier", "this.is.my.nas-identifier.de")
                .addAttribute("NAS-Port", "0");

        logger.info(acc + "\n");
        response = rc.communicate(acc, acctEndpoint).syncUninterruptibly().getNow();
        logger.info("Response: " + response);
*/
        rc.close();

    }
    
    private static void tryPAP(RadiusClient rc, Dictionary dictionary, RadiusEndpoint authEndpoint, String user, String pass, String[] codes) {
        // 1. Send Access-Request
        final AccessRequestPap ar1;
        try {
            ar1 = (AccessRequestPap)
                    ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte) 1, null, Collections.emptyList()))
                            .withPapPassword(pass)
                            .addAttribute("User-Name", user);
//                            .addAttribute("NAS-IP-Address", "192.168.222.1");
        } catch (RadiusPacketException e) {
            e.printStackTrace();
            return;
        }
        RadiusResponse response = rc.communicate(ar1, authEndpoint).syncUninterruptibly().getNow();
        System.out.println("Response from the server:\n\n" + response + "\n");

        byte resType = response.getType();

        int index = 0;
        while(true)  {
            if (resType == PacketType.ACCESS_CHALLENGE) { //challenge packet
                // State Attribute, we have to pass back to radius server for 2nd step login
                byte[] state = response.getAttribute(24).get().getValue();

                final AccessRequestPap ar2;
                try {
                    ar2 = (AccessRequestPap)
                            ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte) 2, null, Collections.emptyList()))
                                    .withPapPassword(codes[index])
                                    .addAttribute("User-Name", user)
                                    .addAttribute(dictionary.createAttribute(-1, 24, state));
//                                .addAttribute("NAS-IP-Address", "192.168.222.1");
                } catch (RadiusPacketException e) {
                    e.printStackTrace();
                    return;
                }

                index++;
                RadiusResponse response2 = rc.communicate(ar2, authEndpoint).syncUninterruptibly().getNow();
                System.out.println("Response from the server:\n\n" + response2 + "\n");

                resType = response2.getType();
                if(resType == PacketType.ACCESS_CHALLENGE) {
                    continue;
                }

                if(resType == PacketType.ACCESS_ACCEPT) {
                    System.out.println("Authentication is successful.");
                }
                else  {
                    System.out.println("Access Denied!");
                }
                break;
            }
            else {
                if(resType == PacketType.ACCESS_ACCEPT) {
                    System.out.println("Authentication is successful.");
                }
                else {
                    System.out.println("Access Denied!");
                }
                break;
            }
        }





    }
    
    private static void tryMSCHAPv2Half(RadiusClient rc, Dictionary dictionary, RadiusEndpoint authEndpoint, String user, String pass, String[] codes) {
        // 1. Send Access-Request
        final AccessRequest ar1;
        try {
            ar1 = (AccessRequest)
                    ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte) 1, null, Collections.emptyList()))
                            .withMSCHapv2Password(user, pass)
                            .addAttribute("User-Name", user);
//                            .addAttribute("NAS-IP-Address", "192.168.222.1");
        } catch (RadiusPacketException e) {
            e.printStackTrace();
            return;
        }
        RadiusResponse response = rc.communicate(ar1, authEndpoint).syncUninterruptibly().getNow();
        System.out.println("Response from the server:\n\n" + response + "\n");

        if (response.getType() == PacketType.ACCESS_CHALLENGE) { //challenge packet
            // State Attribute, we have to pass back to radius server for 2nd step login
            byte[] state = response.getAttribute(24).get().getValue();

            final AccessRequestPap ar2;
            try {
                ar2 = (AccessRequestPap)
                        ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte) 2, null, Collections.emptyList()))
                                .withPapPassword(codes[0])
                                .addAttribute("User-Name", user)
                                .addAttribute(dictionary.createAttribute(-1, 24, state));
//                                .addAttribute("NAS-IP-Address", "192.168.222.1");
            } catch (RadiusPacketException e) {
                e.printStackTrace();
                return;
            }

            RadiusResponse response2 = rc.communicate(ar2, authEndpoint).syncUninterruptibly().getNow();
            System.out.println("Response from the server:\n\n" + response2 + "\n");

            if(response2.getType() == PacketType.ACCESS_ACCEPT) {
                System.out.println("Authentication is successful.");
            }
            else {
                System.out.println("Access Denied!");
            }
        }
        else {
            if(response.getType() == PacketType.ACCESS_ACCEPT) {
                System.out.println("Authentication is successful.");
            }
            else {
                System.out.println("Access Denied!");
            }
        }
    }

    // 2nd step also MSCHAPv2
    private static void tryMSCHAPv2(RadiusClient rc, Dictionary dictionary, RadiusEndpoint authEndpoint, String user, String pass, String[] codes) {
        // 1. Send Access-Request
        final AccessRequest ar1;
        try {
            ar1 = (AccessRequest)
                    ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte) 1, null, Collections.emptyList()))
                            .withMSCHapv2Password(user, pass)
                            .addAttribute("User-Name", user);
//                            .addAttribute("NAS-IP-Address", "192.168.222.1");
        } catch (RadiusPacketException e) {
            e.printStackTrace();
            return;
        }
        RadiusResponse response = rc.communicate(ar1, authEndpoint).syncUninterruptibly().getNow();
        System.out.println("Response from the server:\n\n" + response + "\n");

        if (response.getType() == PacketType.ACCESS_CHALLENGE) { //challenge packet
            // State Attribute, we have to pass back to radius server for 2nd step login
            byte[] state = response.getAttribute(24).get().getValue();

            final AccessRequest ar2;
            try {
                ar2 = (AccessRequest)
                        ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte) 2, null, Collections.emptyList()))
                                .withMSCHapv2Password(user, codes[0])
                                .addAttribute("User-Name", user)
                                .addAttribute(dictionary.createAttribute(-1, 24, state));
//                                .addAttribute("NAS-IP-Address", "192.168.222.1");
            } catch (RadiusPacketException e) {
                e.printStackTrace();
                return;
            }

            RadiusResponse response2 = rc.communicate(ar2, authEndpoint).syncUninterruptibly().getNow();
            System.out.println("Response from the server:\n\n" + response2 + "\n");

            if(response2.getType() == PacketType.ACCESS_ACCEPT) {
                System.out.println("Authentication is successful.");
            }
            else {
                System.out.println("Access Denied!");
            }
        }
        else {
            if(response.getType() == PacketType.ACCESS_ACCEPT) {
                System.out.println("Authentication is successful.");
            }
            else {
                System.out.println("Access Denied!");
            }
        }
    }

}
