package com.yc.shiro.realm;

import com.yc.shiro.beans.User;
import com.yc.shiro.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

public class UserRealm extends AuthorizingRealm {

    @Resource
    private UserService userService;

    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    /**
     * 授权
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    /**
     * 认证
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //获取用户输入的用户名
        String username = (String) authenticationToken.getPrincipal();
        //根据用户名在数据库查找该用户
        User dbUser = userService.selectByUsername(username);
        System.out.println(dbUser);
        //如果没有找到，抛出没有该用户异常
        if(dbUser == null){
            throw new UnknownAccountException("用户不存在");
        }
        //如果该用户被锁住，抛出账号被冻结
        if(Boolean.TRUE.equals(dbUser.getLocked())){
            throw new LockedAccountException("该账号被冻结");
        }
        //返回认证信息
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                dbUser.getUsername(),
                dbUser.getPassword(),
                ByteSource.Util.bytes(dbUser.getCredentialsSalt()),
                getName()
        );
        return authenticationInfo;
    }
}
