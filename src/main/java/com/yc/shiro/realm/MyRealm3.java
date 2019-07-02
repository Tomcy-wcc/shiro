package com.yc.shiro.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;

public class MyRealm3 implements Realm {
    @Override
    public String getName() {
        return "myReaml3";
    }

    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        return authenticationToken instanceof UsernamePasswordToken;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String username = (String) authenticationToken.getPrincipal();
        String password = new String((char[])authenticationToken.getCredentials());
        if(!"zhang".equals(username)){
            throw new UnknownAccountException("用户名不存在");
        }
        if(!"123456".equals(password)){
            throw new IncorrectCredentialsException("用户名或密码错误");
        }
        return new SimpleAuthenticationInfo(username+"@163.com", password, getName());
    }
}
