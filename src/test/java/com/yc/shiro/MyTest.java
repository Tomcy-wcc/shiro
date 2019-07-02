package com.yc.shiro;

import org.apache.commons.beanutils.BeanUtilsBean;
import org.apache.commons.beanutils.converters.AbstractConverter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.SimpleByteSource;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Test;

import java.lang.reflect.Array;
import java.security.Key;
import java.util.Arrays;

public class MyTest extends BaseTest{


    @Test
    public void testAES(){
        AesCipherService aesCipherService = new AesCipherService();
        aesCipherService.setKeySize(128); //设置key长度
        //生成key
        Key key = aesCipherService.generateNewKey(128);
        String text = "hello";
        //加密
        String encrptText =
                aesCipherService.encrypt(text.getBytes(), key.getEncoded()).toHex();
        System.out.println(encrptText);
        //解密
        String text2 =
                new String(aesCipherService.decrypt(Hex.decode(encrptText), key.getEncoded()).getBytes());
        System.out.println(text.equals(text2));
    }

    @Test
    public void testJdbcHashPasswordServiceWithRealm6() {
        BeanUtilsBean.getInstance().getConvertUtils().register(new EnumConverter(), JdbcRealm.SaltStyle.class);
        String iniResourcePath = "classpath:shiro-jdbc-hashedCredentialsMatcher.ini";
        String username = "liu";
        String password = "123";
        login(iniResourcePath, username, password);
        Subject subject = getSubject();
        System.out.println(subject.isAuthenticated());
    }

    private class EnumConverter extends AbstractConverter {
        @Override
        protected String convertToString(final Object value) throws Throwable {
            return ((Enum) value).name();
        }

        @Override
        protected Object convertToType(final Class type, final Object value) throws Throwable {
            return Enum.valueOf(type, value.toString());
        }

        @Override
        protected Class getDefaultType() {
            return null;
        }

    }


    @Test
    public void testHashPasswordServiceWithRealm6() {
        String iniResourcePath = "classpath:shiro-hashedCredentialsMatch.ini";
        String username = "liu";
        String password = "123";
        login(iniResourcePath, username, password);
        Subject subject = getSubject();
        System.out.println(subject.isAuthenticated());
    }

    /**
     * 加密，既有私盐又有公盐
     */
    @Test
    public void testHashPasswordService() {
        String algorithmName = "md5";
        String username = "wcc";
        String password = "123";
        String salt1 = username;
        String salt2 = new SecureRandomNumberGenerator().nextBytes().toHex();
        //System.out.println(salt2);
        int hashIterations = 2;
        SimpleHash hash = new SimpleHash(algorithmName, password, salt1 + "8e1d893ee6d202fddfb4fc82db1d912b", hashIterations);
        System.out.println(hash.toHex());
    }


    /**
     * 加密，只有私盐
     */
    @Test
    public void testPasswordService() {
        String iniResourcePath = "classpath:shiro-passwordservice.ini";
        String username = "wu";
        String password = "123";
        login(iniResourcePath, username, password);
        Subject subject = getSubject();
        System.out.println(subject.isAuthenticated());
        DefaultPasswordService defaultPasswordService = new DefaultPasswordService();
        String encryptPassword = defaultPasswordService.encryptPassword("123");
        System.out.println(encryptPassword);
    }

    @Test
    public void testHashService() {
        DefaultHashService hashService = new DefaultHashService(); //默认算法SHA-512
        hashService.setHashAlgorithmName("SHA-512");
        hashService.setPrivateSalt(new SimpleByteSource("123")); //私盐，默认无
        hashService.setGeneratePublicSalt(true);//是否生成公盐，默认false
        hashService.setRandomNumberGenerator(new SecureRandomNumberGenerator());//用于生成公盐。默认就这个
        hashService.setHashIterations(1); //生成Hash值的迭代次数
        HashRequest request = new HashRequest.Builder()
                .setAlgorithmName("MD5").setSource(ByteSource.Util.bytes("hello"))
                .setSalt(ByteSource.Util.bytes("123")).setIterations(1).build();
        String hex = hashService.computeHash(request).toHex();
        System.out.println(hex);
    }

    /**
     * 散列算法md5
     */
    @Test
    public void hash() {
        String a = "hello";
        String salt = "123";
        String s = new Md5Hash(a, salt, 2).toString();
        System.out.println(s);
    }

    /**
     * shiro中Base64编码和解码和16进制字符串编码/解码
     */
    @Test
    public void encodeAndDecode() {
        String a = "你好啊";

        String encodeToString = Base64.encodeToString(((String) a).getBytes());
        System.out.println(encodeToString);
        String decodeToString = Base64.decodeToString(encodeToString);
        System.out.println(decodeToString);

        String hexEncode = Hex.encodeToString(a.getBytes());
        System.out.println(hexEncode);
        String hexDecode = new String(Hex.decode(hexEncode.getBytes()));
        System.out.println(hexDecode);

        byte[] bytes = CodecSupport.toBytes(a, "utf-8");
        System.out.println(Arrays.toString(bytes));
        System.out.println(Arrays.toString(a.getBytes()));

    }



    /**
     * shiro身份验证
     */
    @Test
    public void loginTest() {
        String iniResourcePath = "classpath:shiro.ini";
        String username = "zhang";
        String password = "111";
        login(iniResourcePath, username, password);
        Subject subject = getSubject();
        //是否验证成功
        boolean isAuthenticated = subject.isAuthenticated();
        System.out.println("是否通过认证：" + isAuthenticated);
        //退出
        subject.logout();
    }

    /**
     * Realm：可以把Realm看成DataSource，即安全数据源
     */
    @Test
    public void realmTest() {
        String iniResourcePath = "classpath:shiro-realm.ini";
        String username = "zhangsan";
        String password = "111111";
        login(iniResourcePath, username, password);
        Subject subject = getSubject();
        //是否验证成功
        boolean isAuthenticated = subject.isAuthenticated();
        System.out.println("是否通过认证：" + isAuthenticated);
        //退出
        subject.logout();
    }

    /**
     * jdbcRealm
     */
    @Test
    public void jdbcRealmTest() {
        String iniResourcePath = "classpath:shiro-jdbc-realm.ini";
        String username = "zhang";
        String password = "123";
        login(iniResourcePath, username, password);
        Subject subject = getSubject();
        //是否验证成功
        boolean isAuthenticated = subject.isAuthenticated();
        System.out.println("是否通过认证：" + isAuthenticated);
        //退出
        subject.logout();
    }

    /**
     * 认证
     * 一个主体（subject）可以有多个身份（principals）
     * 认证器策略
     * FirstSuccessfulStrategy：只要有一个 Realm 验证成功即可，只返回第一个 Realm 身份验证 成功的认证信息，其他的忽略
     * AtLeastOneSuccessfulStrategy：只要有一个 Realm 验证成功即可，和 FirstSuccessfulStrategy 不同，返回所有 Realm 身份验证成功的认证信息
     * AllSuccessfulStrategy：所有 Realm 验证成功才算成功，且返回所有 Realm 身份验证成功的 认证信息，如果有一个失败就失败了
     * ModularRealmAuthenticator 默认使用 AtLeastOneSuccessfulStrategy 策略
     */
    @Test
    public void AuthenticatorTest() {
        String iniResourcePath = "classpath:shiro-authenticator-all-success.ini";
        String username = "zhang";
        String password = "123456";
        login(iniResourcePath, username, password);
        Subject subject = getSubject();
        PrincipalCollection principals = subject.getPrincipals();
        System.out.println(principals.asList());
        subject.logout();
    }

    /**
     * 授权
     */
    @Test
    public void testHasRole() {
        String iniResourcePath = "classpath:shiro-role.ini";
        String username = "zhang";
        String password = "123";
        login(iniResourcePath, username, password);
        Subject subject = getSubject();
        //判断用户是否有相应的角色
        //hasRole()返回true/false
        System.out.println(subject.hasRole("role1"));
        System.out.println(subject.hasAllRoles(Arrays.asList("role1", "role2")));
        //checkRole()会抛出异常
        //subject.checkRole("role3");
        //判断角色是否有相应的权限，（之前先获取该用户的角色）
        //isPermitted()
        System.out.println(subject.isPermitted("user:create"));
    }

    /**
     * 自定义授权规则
     */
    @Test
    public void testIsPermitted() {
        String iniResourcePath = "classpath:shiro-jdbc-authorizer.ini";
        String username = "zhang";
        String password = "123";
        login(iniResourcePath, username, password);
        Subject subject = getSubject();
        System.out.println(subject.isPermitted("user1:*"));
        System.out.println(subject.hasRole("role1"));
        subject.logout();
    }


}
