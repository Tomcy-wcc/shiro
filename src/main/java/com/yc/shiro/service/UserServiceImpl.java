package com.yc.shiro.service;

import com.yc.shiro.beans.User;
import com.yc.shiro.mapper.UserMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service("userService")
public class UserServiceImpl implements UserService {

    @Resource
    private UserMapper userMapper;

    @Resource
    private PasswordService passwordService;

    @Override
    public List<User> selectAll() {
        return userMapper.selectAll();
    }

    @Override
    public int createUser(User user) {
        passwordService.encryptPassword(user);

        return userMapper.createUser(user);
    }

    @Override
    public User selectByUsername(String username) {
        return userMapper.selectByUsername(username);
    }

}
