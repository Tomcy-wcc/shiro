package com.yc.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;

public class BaseTest {
    /**
     * login功能
     *
     * @param iniResourcePath
     * @param username
     * @param password
     */
    public void login(String iniResourcePath, String username, String password) {
        //创建SecurityManager工厂
        Factory<SecurityManager> factory = new IniSecurityManagerFactory(iniResourcePath);
        //获取SecurityManager 实例
        SecurityManager securityManager = factory.getInstance();
        //将SecurityManager实例绑定到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        //获取subject实例
        Subject subject = SecurityUtils.getSubject();
        //创建身份验证token
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);
        //身份验证（登入）
        try {
            //身份验证（登入）
            subject.login(usernamePasswordToken);
        } catch (AuthenticationException e) {
            //身份验证失败
            System.out.println(e.getMessage());
        }
    }

    /**
     * 获取主题
     *
     * @return
     */
    public Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    @After
    public void tearDown() throws Exception {
        ThreadContext.unbindSubject();//退出时请解除绑定Subject到线程 否则对下次测试造成影响
    }
}
