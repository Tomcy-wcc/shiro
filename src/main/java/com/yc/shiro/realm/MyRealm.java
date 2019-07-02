package com.yc.shiro.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;

public class MyRealm implements Realm {
    @Override
    public String getName() {
        return "myRealm";
    }

    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        //仅支持UsernamePasswordToken认证
        return authenticationToken instanceof UsernamePasswordToken;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String username = (String) authenticationToken.getPrincipal();
        String password = new String((char[])authenticationToken.getCredentials());
        System.out.println(username+"---->"+password);
        if(!"zhangsan".equals(username)){
            throw new UnknownAccountException("用户名不存在");
        }
        if(!"111111".equals(password)){
            throw new IncorrectCredentialsException("用户名或密码错误");
        }
        return new SimpleAuthenticationInfo(username, password, getName());
    }
}
