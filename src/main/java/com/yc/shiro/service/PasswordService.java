package com.yc.shiro.service;

import com.yc.shiro.beans.User;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
import org.springframework.stereotype.Service;

@Service("passwordService")
public class PasswordService {

    private RandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();

    private String algorithmName = "md5";

    private final int hashIterations = 2;

    public void encryptPassword(User user){

        String salt = randomNumberGenerator.nextBytes().toHex();

        user.setSalt(salt);

        String newPassword = new SimpleHash(algorithmName, user.getPassword(), ByteSource.Util.bytes(user.getCredentialsSalt()), hashIterations).toHex();

        user.setPassword(newPassword);

    }

}
