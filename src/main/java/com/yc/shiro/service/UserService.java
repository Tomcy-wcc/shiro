package com.yc.shiro.service;

import com.yc.shiro.beans.User;

import java.util.List;

public interface UserService {
    List<User> selectAll();

    int createUser(User user);

    User selectByUsername(String username);
}
