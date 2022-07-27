package org.example.services.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
@Slf4j
@SuppressWarnings("restriction")
public class RSAUtils {

	/**
	 * 加密算法RSA
	 */
	public static final String KEY_ALGORITHM = "RSA";

	/**
	 * 签名算法
	 */
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

	public static final Integer BLOCK_LENGTH = 128;

	public static final Integer DECRYPT_BLOCK_LENGTH = 117;


	/**
	 * <p>
	 * 私钥解密
	 * </p>
	 *
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(String key, String data) throws Exception {
		byte[] decryptBody = new Base64().decode(data);// 返回body
		byte[] keyBytes = new Base64().decode(key);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateK);
		byte[] decryptedData = cipher.doFinal(decryptBody);
		return new String(decryptedData, "UTF-8");
	}

	/**
	 * 私钥分段解密
	 */
	public static String decryptByBlock(String key, String data) throws Exception {
		byte[] encryptedData = new Base64().decode(data);// 返回body
		byte[] keyBytes = new Base64().decode(key);

		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());// keyFactory.getAlgorithm()
		cipher.init(Cipher.DECRYPT_MODE, privateK);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;

		byte[] decryptedData;
		int i = 0;
		// 对数据分段解密
		if (inputLen > BLOCK_LENGTH) {
			byte[] cache;
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > BLOCK_LENGTH) {
					cache = cipher.doFinal(encryptedData, offSet, BLOCK_LENGTH);
				} else {
					cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * BLOCK_LENGTH;
			}
			decryptedData = out.toByteArray();
		} else {
			decryptedData = cipher.doFinal(encryptedData);
		}

		out.close();
		return new String(decryptedData, "UTF-8");
	}

	/**
	 * 公钥加密过程
	 * 
	 *            公钥
	 * @param plainTextData
	 *            明文数据
	 * @return
	 * @throws Exception
	 *             加密过程中的异常信息
	 */
	public static String encrypt(String key, byte[] plainTextData) throws Exception {
		byte[] keyByte = new Base64().decode(key.getBytes());
		Cipher cipher = null;
		try {
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyByte);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			Key publicK = keyFactory.generatePublic(x509KeySpec);
			// 使用默认RSA
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicK);
			byte[] output = cipher.doFinal(plainTextData);
			return new Base64().encodeToString(output);
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此加密算法");
		} catch (NoSuchPaddingException e) {
			//log.error("处理加解密异常，{}", e);
			return null;
		} catch (InvalidKeyException e) {
			throw new Exception("加密公钥非法,请检查");
		} catch (IllegalBlockSizeException e) {
			throw new Exception("明文长度非法");
		} catch (BadPaddingException e) {
			throw new Exception("明文数据已损坏");
		}
	}

	/**
	 * 公钥加密过程
	 *
	 *            公钥
	 * @param plainTextData
	 *            明文数据
	 * @return
	 * @throws Exception
	 *             加密过程中的异常信息
	 */
	public static String encryptByBlock(String key, byte[] plainTextData) throws Exception {
		byte[] keyByte = new Base64().decode(key.getBytes());
		Cipher cipher = null;
		try {
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyByte);
			KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			Key publicK = keyFactory.generatePublic(x509KeySpec);
			// 使用默认RSA
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicK);

			int inputLen = plainTextData.length;
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			int offSet = 0;
			byte[] decryptedData;
			int i = 0;
			// 对数据分段解密
			if (inputLen > DECRYPT_BLOCK_LENGTH) {

				byte[] cache;
				while (inputLen - offSet > 0) {
					if (inputLen - offSet > DECRYPT_BLOCK_LENGTH) {
						cache = cipher.doFinal(plainTextData, offSet, DECRYPT_BLOCK_LENGTH);
					} else {
						cache = cipher.doFinal(plainTextData, offSet, inputLen - offSet);
					}
					out.write(cache, 0, cache.length);
					i++;
					offSet = i * DECRYPT_BLOCK_LENGTH;
				}
				decryptedData = out.toByteArray();
			} else {
				decryptedData = cipher.doFinal(plainTextData);
			}

			out.close();

			return new Base64().encodeToString(decryptedData);
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此加密算法");
		} catch (NoSuchPaddingException e) {
			log.error("处理加解密异常，{}", e);
			return null;
		} catch (InvalidKeyException e) {
			throw new Exception("加密公钥非法,请检查");
		} catch (IllegalBlockSizeException e) {
			throw new Exception("明文长度非法");
		} catch (BadPaddingException e) {
			throw new Exception("明文数据已损坏");
		}
	}

	public static byte[] decryptBase64(String key) throws Exception {
		return (new BASE64Decoder()).decodeBuffer(key);
	}

	public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
		byte[] keyBytes = decryptBase64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(2, privateK);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;

		for(int i = 0; inputLen - offSet > 0; offSet = i * BLOCK_LENGTH) {
			byte[] cache;
			if (inputLen - offSet > BLOCK_LENGTH) {
				cache = cipher.doFinal(encryptedData, offSet, BLOCK_LENGTH);
			} else {
				cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
			}

			out.write(cache, 0, cache.length);
			++i;
		}

		byte[] decryptedData = out.toByteArray();
		out.close();
		return decryptedData;
	}

	public static String decryptDataOnJava(String data, String PRIVATEKEY) throws Exception {
		byte[] rs = decryptBase64(data);
		return new String(decryptByPrivateKey(rs, PRIVATEKEY), "UTF-8");
	}
}
