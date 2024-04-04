package org.tinyradius.io;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.util.HashedWheelTimer;
import io.netty.util.Timer;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
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
        if (args.length < 4) {
            System.out.println("Usage: TestClient hostName sharedSecret userName protocol [timeout]");
            System.out.println("protocol: 1=PAP, 2=MSCHAPv2 then OTP, 3=MSCHAPv2 then MSCHAPv2");

            return;
        }

        Configurator.setRootLevel(Level.WARN);  //change the log level

        final String host = args[0];
        final String shared = args[1];
        final String user = args[2];
        final String protocol = args[3];

        int timeoutMs = 2000;
        if(args.length > 4) {
            try {
                timeoutMs = Integer.parseInt(args[4]);
                timeoutMs = timeoutMs*1000;

            } catch (NumberFormatException e) {
                System.out.println("Invalid integer input");
            }
        }

        final NioEventLoopGroup eventLoopGroup = new NioEventLoopGroup(4);

        final Dictionary dictionary = DefaultDictionary.INSTANCE;
        final Timer timer = new HashedWheelTimer();

        final Bootstrap bootstrap = new Bootstrap().group(eventLoopGroup).channel(NioDatagramChannel.class);

        final RadiusClient rc = new RadiusClient(
                bootstrap, new InetSocketAddress(0), new FixedTimeoutHandler(timer,1, timeoutMs), new ChannelInitializer<DatagramChannel>() {
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
                tryPAP(rc, dictionary, authEndpoint, user);
                break;
            case "2":
                System.out.println("MSCHAPv2 on the first step, but PAP on the second step.");
                tryMSCHAPv2Half(rc, dictionary, authEndpoint, user);
                break;
            default:
                System.out.println("MSCHAPv2 on both steps.");
                tryMSCHAPv2(rc, dictionary, authEndpoint, user);
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
    
    private static void tryPAP(RadiusClient rc, Dictionary dictionary, RadiusEndpoint authEndpoint, String user) {


        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        String strPrompt = "Please enter AD password:";
        byte[] state={30,40};
        int index = 0;
        while(true)  {
            System.out.println(strPrompt);
            String strCode="";
            try {
                strCode = reader.readLine();
            } catch (IOException e) {
                e.printStackTrace();
            }

            // 1. Send Access-Request
            AccessRequest ar;
            try {
                if(index>0) {
                    ar = (AccessRequest)
                            ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte)(index+1), null, Collections.emptyList()))
                                    .withPapPassword(strCode)
                                    .addAttribute(dictionary.createAttribute(-1, 24, state))
                                    .addAttribute("User-Name", user);
                }
                else {
                    ar = (AccessRequest)
                            ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte)(index+1), null, Collections.emptyList()))
                                    .withPapPassword(strCode)
                                    .addAttribute("User-Name", user);
                }

            } catch (RadiusPacketException e) {
                e.printStackTrace();
                return;
            }

            RadiusResponse response = rc.communicate(ar, authEndpoint).syncUninterruptibly().getNow();
//            System.out.println("Response from the server:\n\n" + response + "\n");

            byte resType = response.getType();


            index++;
            if (resType == PacketType.ACCESS_CHALLENGE) { //challenge packet
                // State Attribute, we have to pass back to radius server for 2nd step login
                state = response.getAttribute(24).get().getValue();
                strPrompt = response.getAttribute(18).get().getValueString();
                continue;
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
    
    private static void tryMSCHAPv2Half(RadiusClient rc, Dictionary dictionary, RadiusEndpoint authEndpoint, String user) {

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        String strPrompt = "Please enter AD password:";
        byte[] state={30,40};
        int index = 0;
        while(true)  {
            System.out.println(strPrompt);
            String strCode="";
            try {
                strCode = reader.readLine();
            } catch (IOException e) {
                e.printStackTrace();
            }

            // 1. Send Access-Request
            AccessRequest ar;
            try {
                if(index>0) {
                    ar = (AccessRequest)
                            ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte)(index+1), null, Collections.emptyList()))
                                    .withPapPassword(strCode)
                                    .addAttribute(dictionary.createAttribute(-1, 24, state))
                                    .addAttribute("User-Name", user);
                }
                else {
                    ar = (AccessRequest)
                            ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte)(index+1), null, Collections.emptyList()))
                                    .withMSCHapv2Password(user, strCode)
                                    .addAttribute("User-Name", user);
                }

            } catch (RadiusPacketException e) {
                e.printStackTrace();
                return;
            }

            RadiusResponse response = rc.communicate(ar, authEndpoint).syncUninterruptibly().getNow();
//            System.out.println("Response from the server:\n\n" + response + "\n");

            byte resType = response.getType();


            index++;
            if (resType == PacketType.ACCESS_CHALLENGE) { //challenge packet
                // State Attribute, we have to pass back to radius server for 2nd step login
                state = response.getAttribute(24).get().getValue();
                strPrompt = response.getAttribute(18).get().getValueString();
                continue;
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

    // 2nd step also MSCHAPv2
    private static void tryMSCHAPv2(RadiusClient rc, Dictionary dictionary, RadiusEndpoint authEndpoint, String user) {

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        String strPrompt = "Please enter AD password:";
        byte[] state={30,40};
        int index = 0;
        while(true)  {
            System.out.println(strPrompt);
            String strCode="";
            try {
                strCode = reader.readLine();
            } catch (IOException e) {
                e.printStackTrace();
            }

            // 1. Send Access-Request
            AccessRequest ar;
            try {
                if(index>0) {
                    ar = (AccessRequest)
                            ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte)(index+1), null, Collections.emptyList()))
                                    .withMSCHapv2Password(user, strCode)
                                    .addAttribute(dictionary.createAttribute(-1, 24, state))
                                    .addAttribute("User-Name", user);
                }
                else {
                    ar = (AccessRequest)
                            ((AccessRequest) RadiusRequest.create(dictionary, ACCESS_REQUEST, (byte)(index+1), null, Collections.emptyList()))
                                    .withMSCHapv2Password(user, strCode)
                                    .addAttribute("User-Name", user);
                }

            } catch (RadiusPacketException e) {
                e.printStackTrace();
                return;
            }

            RadiusResponse response = rc.communicate(ar, authEndpoint).syncUninterruptibly().getNow();
//            System.out.println("Response from the server:\n\n" + response + "\n");

            byte resType = response.getType();


            index++;
            if (resType == PacketType.ACCESS_CHALLENGE) { //challenge packet
                // State Attribute, we have to pass back to radius server for 2nd step login
                state = response.getAttribute(24).get().getValue();
                strPrompt = response.getAttribute(18).get().getValueString();
                continue;
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

}
