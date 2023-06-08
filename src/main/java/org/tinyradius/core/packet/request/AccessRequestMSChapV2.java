package org.tinyradius.core.packet.request;

import io.netty.buffer.ByteBuf;
import org.tinyradius.core.RadiusPacketException;
import org.tinyradius.core.attribute.type.RadiusAttribute;
import org.tinyradius.core.attribute.type.VendorSpecificAttribute;
import org.tinyradius.core.dictionary.Dictionary;
import org.tinyradius.core.packet.RadiusPacket;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * https://insinuator.net/2013/08/vulnerabilities-attack-vectors-of-vpns-pt-1/
 * https://www.schneier.com/wp-content/uploads/2015/12/paper-pptpv2.pdf
 */
public class AccessRequestMSChapV2 extends AccessRequest {

    private static final byte CHAP_CHALLENGE = 60;

    public AccessRequestMSChapV2(Dictionary dictionary, ByteBuf header, List<RadiusAttribute> attributes) throws RadiusPacketException {
        super(dictionary, header, attributes);
    }

    static AccessRequest withPassword(AccessRequest request, String username, String password) throws RadiusPacketException {
        final List<RadiusAttribute> attributes = withPasswordAttribute(request.getDictionary(), request.getAttributes(), username, password);
        final ByteBuf header = RadiusPacket.buildHeader(request.getType(), request.getId(), request.getAuthenticator(), attributes);
        return create(request.getDictionary(), header, attributes);
    }

    /**
     * Set CHAP-Password / CHAP-Challenge attributes with provided password.
     * <p>
     * Will remove existing attributes if exists already
     *
     * @param password plaintext password to encode into CHAP-Password
     * @return AccessRequestChap with encoded CHAP-Password and CHAP-Challenge attributes
     * @throws IllegalArgumentException invalid password
     */
    private static List<RadiusAttribute> withPasswordAttribute(Dictionary dictionary, List<RadiusAttribute> attributes, String username, String password) {
        if (password == null || password.isEmpty())
            throw new IllegalArgumentException("Could not encode CHAP attributes, password not set");

        // MS-CHAP-Challenge    
        // This Attribute contains the challenge sent by a NAS to a Microsoft Challenge-Handshake Authentication Protocol (MS-CHAP) user.
        //These two should be passed in as parameters
        final byte[] challenge = random16bytes();   // MS-CHAP-CHALLENGE,
        final byte[] peerChallenge = random16bytes();

        final List<RadiusAttribute> newAttributes = attributes.stream()
                .filter(a -> !(a.getVendorId() == -1 && a.getType() == CHAP_PASSWORD)
                        && !(a.getVendorId() == -1 && a.getType() == CHAP_CHALLENGE))
                .collect(Collectors.toList());


        try {
            byte[] passwordBytes = password.getBytes("UTF-16LE");

            byte[] ntHash = hashNt(passwordBytes);



            byte[] challenge8 = ChallengeHash(peerChallenge, challenge, username);
            
            byte[] ntResponse = ChallengeResponse(challenge8,ntHash);

            //https://freeradius.org/rfc/rfc2548.html
            byte[] msChap2Challenge = calculateMSCHAP2Response(peerChallenge, ntResponse);
            

            //vendorID 311, Microsoft
            VendorSpecificAttribute vsa = new VendorSpecificAttribute(dictionary, 311, Arrays.asList(
                dictionary.createAttribute(311, 11,challenge),
                dictionary.createAttribute(311, 25,msChap2Challenge)
            ));
            newAttributes.add(vsa);

        } catch (Exception e) {
            e.printStackTrace();
        }
        


        return newAttributes;
    }

    @Override
    public RadiusRequest encodeRequest(String sharedSecret) throws RadiusPacketException {
        validateChapAttributes();
        return super.encodeRequest(sharedSecret);
    }

    @Override
    public RadiusRequest decodeRequest(String sharedSecret) throws RadiusPacketException {
        validateChapAttributes();
        return super.decodeRequest(sharedSecret);
    }

    /**
     * Encodes a plain-text password using the given CHAP challenge.
     * See RFC 2865 section 2.2
     *
     * @param chapId        CHAP ID associated with request
     * @param plaintextPw   plain-text password
     * @param chapChallenge random 16 octet CHAP challenge
     * @return 17 octet CHAP-encoded password (1 octet for CHAP ID, 16 octets CHAP response)
     */
    private static byte[] computeChapPassword(byte chapId, String plaintextPw, byte[] chapChallenge) {
        final MessageDigest md5 = RadiusPacket.getMd5Digest();
        md5.update(chapId);
        md5.update(plaintextPw.getBytes(UTF_8));
        md5.update(chapChallenge);

        return ByteBuffer.allocate(17)
                .put(chapId)
                .put(md5.digest())
                .array();
    }

    /**
     * Checks that the passed plain-text password matches the password
     * (hash) send with this Access-Request packet.
     *
     * @param password plaintext password to verify packet against
     * @return true if the password is valid, false otherwise
     */
    public boolean checkPassword(String password) {
        if (password == null || password.isEmpty()) {
            logger.warn("Plaintext password to check against is empty");
            return false;
        }

        final byte[] chapChallenge = getAttribute(CHAP_CHALLENGE)
                .map(RadiusAttribute::getValue)
                .orElse(getAuthenticator());

        final byte[] chapPassword = getAttribute(CHAP_PASSWORD)
                .map(RadiusAttribute::getValue)
                .orElse(null);
        if (chapPassword == null || chapPassword.length != 17) {
            logger.warn("CHAP-Password must be 17 bytes");
            return false;
        }

        return Arrays.equals(chapPassword, computeChapPassword(chapPassword[0], password, chapChallenge));
    }

    private void validateChapAttributes() throws RadiusPacketException {
        final int count = filterAttributes(CHAP_PASSWORD).size();
        if (count != 1)
            throw new RadiusPacketException("AccessRequest (CHAP) should have exactly one CHAP-Password attribute, has " + count);
        // CHAP-Challenge can use Request Authenticator instead of attribute
    }
   
    private static byte[] calculateMSCHAP2Response(byte[] peerChallenge, byte[] ntResponse) {
        byte[] msChap2Challenge = new byte[50];
        msChap2Challenge[0] = 1;    //ident for mschap2
        System.arraycopy(peerChallenge, 0, msChap2Challenge, 2, peerChallenge.length);  //16
        System.arraycopy(ntResponse, 0, msChap2Challenge, 26, ntResponse.length);   //24
        return msChap2Challenge;
    }   

    private static byte[] ChallengeHash(byte[] PeerChallenge,  byte[]  AuthenticatorChallenge, String UserName)
    {           
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(PeerChallenge);   // 16 bytes
            md.update(AuthenticatorChallenge);
            
            byte[] fullDigest =  md.digest(UserName.getBytes());
            byte[] Challenge = new byte[8];

            System.arraycopy(fullDigest, 0, Challenge, 0, 8);
            return Challenge;
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }       
     
    }    
    
    private static byte[] ChallengeResponse(byte[]  Challenge,  byte[]  PasswordHash)
    {
       // Set ZPasswordHash to PasswordHash zero-padded to 21 octets
        byte[] key = new byte[7];
        byte[] Response = new byte[24];
        byte[] ZPasswordHash = new byte[21];    // In java all elements(primitive integer types byte short, int, long) are initialised to 0 by default
        System.arraycopy(PasswordHash, 0, Response, 0, 16);
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");    //Challenge 8 byte, so no padding is OK

            System.arraycopy(key, 0, ZPasswordHash, 0, 7);
            SecretKey keySpec = new SecretKeySpec(key, "DES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] out =  cipher.doFinal(Challenge);
            System.arraycopy(out, 0, Response, 0, 8);

            System.arraycopy(key, 0, ZPasswordHash, 7, 7);
            keySpec = new SecretKeySpec(key, "DES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            out =  cipher.doFinal(Challenge);
            System.arraycopy(out, 0, Response, 8, 8);

            System.arraycopy(key, 0, ZPasswordHash, 14, 7);
            keySpec = new SecretKeySpec(key, "DES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            out =  cipher.doFinal(Challenge);
            System.arraycopy(out, 0, Response, 16, 8);
            return Response;

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    
    }

    private static byte[] hashNt(byte[] unicodePassword) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD4");
            return md.digest(unicodePassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }    
}
