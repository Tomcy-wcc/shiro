package com.yc.shiro;


import com.yc.shiro.beans.User;
import com.yc.shiro.service.PasswordService;
import com.yc.shiro.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.annotation.Resource;
import java.util.List;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath:applicationContext.xml"})
public class UserTest{

    @Resource
    private UserService userService;

    @Test
    public void testLogin(){
        Subject subject = SecurityUtils.getSubject();
        String username = "wcc";
        String password = "123";
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);
        subject.login(usernamePasswordToken);
        System.out.println(subject.isAuthenticated());
    }

    @Test
    public void selectByUsername(){
        User wcc = userService.selectByUsername("wcc");
        System.out.println(wcc);
    }

    @Test
    public void selectAll(){
        List<User> users = userService.selectAll();
        System.out.println(users);
    }

    @Test
    public void testCreateUser(){
        int i = userService.createUser(new User("wcc", "123"));
        System.out.println(i);
    }


}
